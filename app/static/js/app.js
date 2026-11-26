document.addEventListener("DOMContentLoaded", function () {
    initDropzone();
    initStatusPolling();
});

function initDropzone() {
    var dropzone = document.getElementById("dropzone");
    var fileInput = document.getElementById("fileInput");

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener("dragover", function (e) {
        e.preventDefault();
        dropzone.classList.add("drag-over");
    });

    dropzone.addEventListener("dragleave", function () {
        dropzone.classList.remove("drag-over");
    });

    dropzone.addEventListener("drop", function (e) {
        e.preventDefault();
        dropzone.classList.remove("drag-over");
        var files = e.dataTransfer.files;
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    });

    fileInput.addEventListener("change", function () {
        if (fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
        }
    });
}

function uploadFile(file) {
    var progressSection = document.getElementById("uploadProgress");
    var resultSection = document.getElementById("uploadResult");
    var fileNameSpan = document.getElementById("uploadFileName");
    var percentSpan = document.getElementById("uploadPercent");
    var progressBar = document.getElementById("progressBar");
    var statusText = document.getElementById("uploadStatus");
    var dropzone = document.getElementById("dropzone");

    progressSection.classList.remove("hidden");
    resultSection.classList.add("hidden");
    dropzone.style.display = "none";
    fileNameSpan.textContent = file.name;
    percentSpan.textContent = "0%";
    progressBar.style.width = "0%";
    statusText.textContent = "Uploading...";

    var formData = new FormData();
    formData.append("file", file);

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload", true);

    xhr.upload.addEventListener("progress", function (e) {
        if (e.lengthComputable) {
            var percent = Math.round((e.loaded / e.total) * 100);
            percentSpan.textContent = percent + "%";
            progressBar.style.width = percent + "%";
            if (percent === 100) {
                statusText.textContent = "Processing...";
            }
        }
    });

    xhr.addEventListener("load", function () {
        var response;
        try {
            response = JSON.parse(xhr.responseText);
        } catch (e) {
            var preview = xhr.responseText ? xhr.responseText.substring(0, 200) : "(empty)";
            showResult("error", "Server returned non-JSON response (HTTP " + xhr.status + "): " + preview);
            return;
        }

        if (xhr.status === 202) {
            showResult(
                "success",
                'Analysis started. Job ID: <strong>' + response.job_id + '</strong>. ' +
                '<a href="/report/' + response.job_id + '" style="color: inherit; text-decoration: underline;">View Report</a>'
            );
            setTimeout(function () {
                location.reload();
            }, 2000);
        } else if (xhr.status === 200 && response.duplicate) {
            showResult(
                "info",
                'This file has already been analyzed. ' +
                '<a href="/report/' + response.job_id + '" style="color: inherit; text-decoration: underline;">View Existing Report</a>'
            );
        } else if (response.error) {
            showResult("error", response.error);
        } else {
            showResult("error", "Unexpected response from server.");
        }
    });

    xhr.addEventListener("error", function () {
        showResult("error", "Network error. Please check your connection and try again.");
    });

    xhr.addEventListener("timeout", function () {
        showResult("error", "Upload timed out. Please try again.");
    });

    xhr.timeout = 120000;
    xhr.send(formData);
}

function showResult(type, message) {
    var resultSection = document.getElementById("uploadResult");
    var progressSection = document.getElementById("uploadProgress");

    progressSection.classList.add("hidden");
    resultSection.classList.remove("hidden");
    resultSection.className = "upload-result " + type;
    resultSection.innerHTML = '<p>' + message + '</p>';
}

function initStatusPolling() {
    // Re-query rows every tick so we always have the live set
    var intervalId = setInterval(function () {
        var rows = document.querySelectorAll("tr[data-status='QUEUED'], tr[data-status='EXECUTING']");
        if (rows.length === 0) {
            // Nothing left to poll
            clearInterval(intervalId);
            return;
        }

        rows.forEach(function (row) {
            var jobId = row.getAttribute("data-job-id");
            var currentStatus = row.getAttribute("data-status");

            if (currentStatus === "COMPLETED" || currentStatus === "FAILED") return;

            fetch("/api/status/" + jobId)
                .then(function (resp) {
                    if (!resp.ok) throw new Error("HTTP " + resp.status);
                    return resp.json();
                })
                .then(function (data) {
                    if (data.status !== currentStatus) {
                        row.setAttribute("data-status", data.status);
                        var badge = row.querySelector(".status-badge");
                        if (badge) {
                            badge.className = "status-badge status-" + data.status.toLowerCase();
                            badge.textContent = data.status;
                        }
                        var actionCell = row.querySelector("td:last-child");
                        if (data.status === "COMPLETED" && actionCell) {
                            actionCell.innerHTML = '<a href="/report/' + jobId + '" class="btn btn-sm btn-primary">View Report</a>';
                        } else if (data.status === "FAILED" && actionCell) {
                            actionCell.innerHTML = '<span class="btn btn-sm btn-ghost disabled">Failed</span>';
                        }
                    }
                })
                .catch(function (err) {
                    console.warn("Status poll error for job " + jobId + ":", err);
                });
        });
    }, 3000);
}

function copyRule() {
    var ruleText = document.getElementById("ruleText");
    var btn = document.getElementById("copyRuleBtn");

    if (!ruleText) return;

    var text = ruleText.textContent;

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
            btn.textContent = "Copied!";
            setTimeout(function () { btn.textContent = "Copy Rule"; }, 2000);
        }).catch(function () {
            fallbackCopy(text, btn);
        });
    } else {
        fallbackCopy(text, btn);
    }
}

function fallbackCopy(text, btn) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand("copy");
        btn.textContent = "Copied!";
        setTimeout(function () { btn.textContent = "Copy Rule"; }, 2000);
    } catch (e) {
        btn.textContent = "Copy failed";
        setTimeout(function () { btn.textContent = "Copy Rule"; }, 2000);
    }
    document.body.removeChild(textarea);
}

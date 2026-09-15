// Click a finding row to show or hide its full API list.
document.querySelectorAll("tr.row").forEach(function (row) {
  row.addEventListener("click", function () {
    var next = row.nextElementSibling;
    if (next && next.classList.contains("detail")) {
      next.hidden = !next.hidden;
    }
  });
});

// Click a column header to sort a table by that column.
// Each data row has a matching hidden detail row right after it.
// A sort must move both rows together, in the same order.
document.querySelectorAll("table").forEach(function (table) {
  table.querySelectorAll("th").forEach(function (th, col) {
    var ascending = true;
    th.addEventListener("click", function () {
      table.querySelectorAll("th").forEach(function (h) {
        h.classList.remove("asc", "desc");
      });

      var body = table.tBodies[0];
      var pairs = [];
      Array.prototype.forEach.call(body.rows, function (row) {
        if (row.classList.contains("row")) {
          pairs.push([row, row.nextElementSibling]);
        }
      });

      pairs.sort(function (a, b) {
        var x = a[0].cells[col].textContent.trim();
        var y = b[0].cells[col].textContent.trim();
        return ascending ? x.localeCompare(y) : y.localeCompare(x);
      });

      pairs.forEach(function (pair) {
        body.appendChild(pair[0]);
        if (pair[1]) {
          body.appendChild(pair[1]);
        }
      });

      th.classList.add(ascending ? "asc" : "desc");
      ascending = !ascending;
    });
  });
});

// Format a Date as dd/mm/yyyy hh:mm:ss, in the visitor's own time zone.
// This ignores the browser's locale on purpose: toLocaleString() would
// otherwise show mm/dd/yyyy for a US-locale browser, which reads as a
// different date to most of the world.
function formatTimestamp(date) {
  function pad(n) {
    return String(n).padStart(2, "0");
  }
  var day = pad(date.getDate());
  var month = pad(date.getMonth() + 1);
  var year = date.getFullYear();
  var hours = pad(date.getHours());
  var minutes = pad(date.getMinutes());
  var seconds = pad(date.getSeconds());
  return day + "/" + month + "/" + year + " " + hours + ":" + minutes + ":" + seconds;
}

// Show every <time> element in the visitor's own time zone.
document.querySelectorAll("time[datetime]").forEach(function (el) {
  var parsed = new Date(el.getAttribute("datetime"));
  if (!isNaN(parsed)) {
    el.textContent = formatTimestamp(parsed);
  }
});

// While a scan runs, show an hourglass on the Scan button.
// This only runs on the live dashboard. The exported report has no
// Scan button, so scanForm is null there and this block does nothing.
var scanForm = document.getElementById("scan");
if (scanForm) {
  scanForm.addEventListener("submit", function () {
    var button = scanForm.querySelector("button");
    var hourglass = document.getElementById("icon-hourglass");
    button.disabled = true;
    button.classList.add("pending");
    button.title = "Scanning\u2026";
    button.setAttribute("aria-label", "Scanning\u2026");
    if (hourglass) {
      button.innerHTML = hourglass.innerHTML;
    }
  });
}

// The Print button has no inline onclick attribute. The page's
// Content-Security-Policy does not allow inline event handlers, so the
// click handler is set up here instead.
var printBtn = document.getElementById("print-btn");
if (printBtn) {
  printBtn.addEventListener("click", function () {
    window.print();
  });
}

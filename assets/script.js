// Generate Table of Contents (TOC)
document.addEventListener("DOMContentLoaded", function() {
  const toc = document.getElementById("toc");
  if (!toc) return;

  const headers = document.querySelectorAll(".content h1, .content h2, .content h3");
  headers.forEach(header => {
    const id = header.textContent.replace(/\s+/g, "-").toLowerCase();
    header.setAttribute("id", id);

    const li = document.createElement("li");
    li.style.marginLeft = header.tagName === "H2" ? "10px" : 
                         header.tagName === "H3" ? "20px" : "0px";

    const a = document.createElement("a");
    a.href = "#" + id;
    a.textContent = header.textContent;

    li.appendChild(a);
    toc.appendChild(li);
  });
});

// Live search (filters page text)
document.getElementById("searchBox").addEventListener("keyup", function() {
  let filter = this.value.toLowerCase();
  let content = document.querySelector(".content");
  let paragraphs = content.querySelectorAll("p, li");

  paragraphs.forEach(p => {
    if (p.textContent.toLowerCase().includes(filter)) {
      p.style.display = "";
    } else {
      p.style.display = "none";
    }
  });
});

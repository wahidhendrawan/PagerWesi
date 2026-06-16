const toggle = document.querySelector(".nav-toggle");
const links = document.querySelector("#nav-links");

if (toggle && links) {
  toggle.addEventListener("click", () => {
    const expanded = toggle.getAttribute("aria-expanded") === "true";
    toggle.setAttribute("aria-expanded", String(!expanded));
    links.classList.toggle("open", !expanded);
  });

  links.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      toggle.setAttribute("aria-expanded", "false");
      links.classList.remove("open");
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('.left-nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const parentDiv = link.closest('.menu-item');
      const subMenu = parentDiv ? parentDiv.querySelector('.sub-menu') : null;
      const arrow = parentDiv ? parentDiv.querySelector('.arrow-icon') : null;

      if (subMenu) {
        e.preventDefault(); // stop page reload
        subMenu.classList.toggle('hidden');
        if (arrow) arrow.classList.toggle('rotated');
      }
      // if no submenu → normal navigation
    });
  });
});

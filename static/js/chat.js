// Add event listeners to item-links for active class toggle
document.querySelectorAll(".list-group-item").forEach((item) => {
  item.addEventListener("click", function (event) {
    event.preventDefault();
    document.querySelectorAll(".list-group-item").forEach((tab) => {
      tab.classList.remove("actived");
    });
    this.classList.add("actived");
  });
});
document.querySelectorAll(".item-links").forEach((link) => {
  link.addEventListener("click", function (event) {
    event.preventDefault();

    // Loại bỏ class "active" khỏi tất cả các mục khác
    document.querySelectorAll(".item-links").forEach((tab) => {
      tab.classList.remove("active");
    });

    // Thêm class "active" vào mục được chọn
    this.classList.add("active");

    // Ẩn tất cả các phần tử có class "tab-content"
    document.querySelectorAll(".tab-content").forEach((tab) => {
      tab.classList.remove("active");
    });

    // Hiển thị phần tử được chọn
    const targetId = this.getAttribute("data-target");
    const chatArea = document.querySelector(".chat-area");
    const selectedTab = document.getElementById(targetId);
    const newContent = selectedTab.innerHTML;
    chatArea.innerHTML = newContent;

    // Update name and description
    const nameElement = document.querySelector(".profile-header h5");
    const descriptionElement = document.querySelector(".profile-header p");
    const newName = this.getAttribute("data-name");
    const newDescription = this.getAttribute("data-description");
    nameElement.textContent = newName;
    descriptionElement.textContent = newDescription;
  });
});

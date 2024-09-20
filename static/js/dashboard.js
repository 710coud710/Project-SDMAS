const searchIcon = document.getElementById("search-icon");
// ===Chuyển mục sidebar===
document.querySelectorAll(".nav-link").forEach((link) => {
  link.addEventListener("click", function (event) {
    event.preventDefault();
    // Loại bỏ class "active" khỏi tất cả các mục khác
    document.querySelectorAll(".nav-link").forEach((tab) => {
      tab.classList.remove("active");
    });

    // Thêm class "active" vào mục được chọn
    this.classList.add("active");

    // Ẩn tất cả các phần tử có class "tab-content"
    document.querySelectorAll(".tab-content").forEach((tab) => {
      tab.classList.remove("active");
    });
    document.getElementById("welcome").classList.remove("active");
    // Hiển thị phần tử được chọn
    const targetId = this.getAttribute("data-target");
    if (targetId === "xem-ki-thuat") {
      document.getElementById(targetId).style.display = "block";
      document.getElementById("form-tim-kiem").style.display = "none";
      document.getElementById("bang-tin").style.display = "none";
    } else if (targetId === "bang-tin") {
      document.getElementById(targetId).style.display = "block";
      document.getElementById("form-tim-kiem").style.display = "none";
      document.getElementById("xem-ki-thuat").style.display = "none";
    } else {
      document.getElementById(targetId).classList.add("active");
      document.getElementById("xem-ki-thuat").style.display = "none";
      document.getElementById("form-tim-kiem").style.display = "none";
      document.getElementById("bang-tin").style.display = "none";
    }
  });
});

// ===CHuyển mục xem tất cả===

document.querySelectorAll(".ki-thuat-link").forEach((xem) => {
  xem.addEventListener("click", function (event) {
    event.preventDefault();
    document.getElementById("xem-ki-thuat").style.display = "none";

    document.querySelectorAll(".xem-tat-ca-ki-thuat").forEach((tab) => {
      tab.classList.remove("active");
    });
    // Hiển thị phần tử được chọn
    const targetId = this.getAttribute("data-target");
    document.getElementById(targetId).classList.add("active");
    document.querySelectorAll(".fa-arrow-left").forEach((arrow) => {
      arrow.addEventListener("click", function () {
        document.getElementById("xem-ki-thuat").style.display = "block";
        document.getElementById(targetId).classList.remove("active");
      });
    });
  });
});

searchIcon.addEventListener("click", function () {
  document.getElementById("form-tim-kiem").style.display = "block";
  document.getElementById("bang-tin").style.display = "none";
  document.getElementById("search-bar-tim-kiem").focus();
});

document.querySelectorAll(".fa-bookmark").forEach((bookmark) => {
  bookmark.addEventListener("click", function () {
    this.classList.toggle("active");
  });
});
// document.addEventListener("click", function (event) {
//   const formTimKiem = document.getElementById("form-tim-kiem");
//   const bangTin = document.getElementById("bang-tin");

//   if (!formTimKiem.contains(event.target) && event.target !== searchIcon) {
//     formTimKiem.style.display = "none";
//     bangTin.style.display = "block";
//   }
// });

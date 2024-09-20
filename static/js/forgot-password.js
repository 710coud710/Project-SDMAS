document.getElementById("otpForm").addEventListener("submit", function (e) {
  e.preventDefault();

  alert("Đã gửi thành công mã OTP!");

  const submitBtn = document.getElementById("submitBtn");
  submitBtn.disabled = true;

  // Bắt đầu đếm ngược 30 giây
  let timeLeft = 30;
  const countdownElement = document.getElementById("countdown");

  const countdownTimer = setInterval(function () {
    if (timeLeft <= 0) {
      clearInterval(countdownTimer);
      countdownElement.innerHTML = "OTP hết hạn!";
      // Enable lại nút sau khi hết thời gian đếm ngược
      submitBtn.disabled = false;
    } else {
      countdownElement.innerHTML = "Thời gian còn lại: " + timeLeft + " giây";
    }
    timeLeft -= 1;
  }, 1000);
});

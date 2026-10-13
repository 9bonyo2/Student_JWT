// [CSP 대응] CSP의 script-src 가 inline 이벤트 핸들러(onsubmit="...")를 차단하므로
// 삭제 확인(confirm) 로직을 외부 스크립트 파일로 분리한다.
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('form.js-confirm-delete').forEach(function (form) {
        form.addEventListener('submit', function (e) {
            if (!confirm('Are you sure you want to delete this user?')) {
                e.preventDefault();
            }
        });
    });
});

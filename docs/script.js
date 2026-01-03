function copyInstall() {
    const cmd = "curl -sL https://raw.githubusercontent.com/emRival/cli-local-share/main/install.sh | bash";
    navigator.clipboard.writeText(cmd).then(() => {
        const icon = document.querySelector('.copy-icon');
        const original = icon.innerText;
        icon.innerText = '✅';
        setTimeout(() => {
            icon.innerText = original;
        }, 2000);
    });
}

// Smooth scroll for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
            behavior: 'smooth'
        });
    });
});

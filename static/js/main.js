// Auto-dismiss flash messages after 4s
document.addEventListener('DOMContentLoaded', () => {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(el => {
        setTimeout(() => {
            el.style.transition = 'opacity .5s';
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 500);
        }, 4000);
    });

    // Password strength indicator
    const pwInput = document.getElementById('password');
    const bar = document.getElementById('strengthBar');
    if (pwInput && bar) {
        pwInput.addEventListener('input', () => {
            const val = pwInput.value;
            let score = 0;
            if (val.length >= 8) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[^A-Za-z0-9]/.test(val)) score++;
            const colors = ['#ff4d6d', '#ffc947', '#4f9eff', '#00c98d'];
            const widths = ['25%', '50%', '75%', '100%'];
            bar.style.width = val.length ? widths[score - 1] || '10%' : '0';
            bar.style.background = val.length ? colors[score - 1] || '#ff4d6d' : 'transparent';
        });
    }
});

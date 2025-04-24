// particles.js
document.addEventListener('DOMContentLoaded', () => {
    // Configuration
    const PARTICLE_COUNT = 120;  // Reduce for better performance
    const SIZE_MIN = 1;       // Minimum particle size in pixels
    const SIZE_MAX = 5;         // Maximum particle size in pixels
    const OPACITY_MIN = 0.3;    // Minimum particle opacity
    const OPACITY_MAX = 0.7;    // Maximum particle opacity
    const ANIMATION_DURATION_MIN = 30;  // Minimum animation duration in seconds
    const ANIMATION_DURATION_MAX = 80;  // Maximum animation duration in seconds

    // Create particles container
    const particlesContainer = document.createElement('div');
    particlesContainer.id = 'particles-container';
    document.body.appendChild(particlesContainer);

    // Generate particles
    for(let i = 0; i < PARTICLE_COUNT; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        
        // Random properties
        const size = Math.random() * (SIZE_MAX - SIZE_MIN) + SIZE_MIN;
        const xMod = Math.random() > 0.5 ? 0.25 : -0.25;
        const yMod = Math.random() > 0.5 ? 0.25 : -0.25;
        const duration = Math.random() * (ANIMATION_DURATION_MAX - ANIMATION_DURATION_MIN) + ANIMATION_DURATION_MIN;
        const delay = Math.random() * -duration;
        const opacity = Math.random() * (OPACITY_MAX - OPACITY_MIN) + OPACITY_MIN;

        // Apply styles
        particle.style.cssText = `
            width: ${size}px;
            height: ${size}px;
            --x-mod: ${xMod};
            --y-mod: ${yMod};
            animation-duration: ${duration}s;
            animation-delay: ${delay}s;
            opacity: ${opacity};
            left: ${Math.random() * 100}%;
            top: ${Math.random() * 100}%;
        `;

        particlesContainer.appendChild(particle);
    }

    // Handle window resize
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            particlesContainer.querySelectorAll('.particle').forEach(particle => {
                particle.style.left = `${Math.random() * 100}%`;
                particle.style.top = `${Math.random() * 100}%`;
            });
        }, 200);
    });
});
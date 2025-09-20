document.addEventListener('DOMContentLoaded', () => {
    // Hide the result div when the page loads
    document.getElementById('verification-result').style.display = 'none';
});

async function handleFileChange(event) {
    const file = event.target.files[0];
    const resultDiv = document.getElementById('verification-result');
    
    if (!file) {
        resultDiv.innerHTML = 'Please select a file to upload.';
        resultDiv.className = 'error';
        resultDiv.style.display = 'block';
        return;
    }

    resultDiv.innerHTML = 'Verifying certificate...';
    resultDiv.className = '';
    resultDiv.style.display = 'block';

    const formData = new FormData();
    formData.append('file', file);

    try {
        // NOTE: Replace with your deployed back-end URL
        const response = await fetch('https://your-backend-service.onrender.com/api/verify', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (response.status === 200) {
            resultDiv.innerHTML = `<strong>Status:</strong> ${data.status}<br>${data.message}`;
            if (data.status === 'Authentic') {
                resultDiv.className = 'success';
            } else {
                resultDiv.className = 'error';
            }
        } else {
            resultDiv.innerHTML = `<strong>Error:</strong> ${data.message}`;
            resultDiv.className = 'error';
        }
    } catch (error) {
        console.error('Network or server error:', error);
        resultDiv.innerHTML = 'An unexpected error occurred. Please try again.';
        resultDiv.className = 'error';
    }
}

function showHowItWorks() {
    alert('How it works: A user uploads a certificate, which is processed by our OCR and AI system. The data is then cross-verified with a secure, centralized database. New certificates can be verified using a unique digital hash for authenticity.');
}
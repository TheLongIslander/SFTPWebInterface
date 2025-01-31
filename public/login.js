document.getElementById('login-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/lovely/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.token) {
            // Store the token in localStorage
            localStorage.setItem('token', data.token);
            // Redirect to the SFTP browser page
            window.location.href = '/lovely/sftp.html';
        } else {
            alert('Login failed: Incorrect Password');
        }
    })
    .catch(err => {
        alert('Login failed');
    });
});

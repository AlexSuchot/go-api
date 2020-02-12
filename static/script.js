document.getElementById("sub-form").addEventListener("submit", e => subscribe(e));
document.getElementById("login-form").addEventListener("submit", e => login(e));
var paragraph = document.getElementById("login-tooltip");
paragraph.textContent = "";

function displayRegister() {
    document.getElementById("sub-form").style.display = 'block';
    document.getElementById("login-form").style.display = 'none';
}

function displayLogin() {
    document.getElementById("sub-form").style.display = 'none';
    document.getElementById("login-form").style.display = 'block';
}

function login(e) {
    let usernameLogin = document.getElementById('username-login').value;
    let passwordLogin = document.getElementById('password-login').value;

    e.preventDefault();

    fetch("http://localhost:1337/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(
            { username: usernameLogin,
                password: passwordLogin
            }
        )
    })
        .then(function (res) {
            console.log(res);
            console.log(res.status);

            if (res.status === 200) {
                paragraph.textContent = "Succesfully logged in !";
            } else {
                paragraph.textContent = "Wrong password or username";
            }
            return res.text();
        })
        .then(function (data) {
            console.log(data);
        }).catch(function (err) {

        console.log(err);
    });
}

function subscribe(e) {
    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;
    let email = document.getElementById('email').value;

    e.preventDefault();

    fetch("http://localhost:1337/subscribe", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(
            { username,
                    password,
                    email
            }
        )
    })
        .then(function (res) {
            console.log(res);
            return res.text();
        })
        .then(function (data) {
            console.log(data);
        }).catch(function (err) {
        console.log(err)
    });
}

let socket = new WebSocket("http://localhost:1337/ws");
socket.onmessage = (msg) => {
    var response = JSON.parse(msg.data);
    var message = document.querySelector('.message');
    message.textContent(response);
};

function sendMessage(e) {
}

function getMessage(e) {

}



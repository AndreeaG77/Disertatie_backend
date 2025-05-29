const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

function sendResetPasswordEmail(to, newPassword) {
    const mailOptions = {
        from: `"MyHomeDesigner" <${process.env.EMAIL_USER}>`,
        to,
        subject: 'Your new password for MyHomeDesigner',
        text: `Hi! Here's your new password: ${newPassword}\nPlease change it after logging in.`,
    };

    return transporter.sendMail(mailOptions);
}

module.exports = { sendResetPasswordEmail };

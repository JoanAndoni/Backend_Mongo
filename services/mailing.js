import nodemailer from 'nodemailer';
import fs from 'fs';

export async function sendEmail(type, data, testing = false) {
    const transporter = testing ? await setTestingAccount() : await setSMTPAccount();
    let email = { subject: '', text: '' };
    var content = '';

    if (type === 1) {
        content = fs.readFileSync('templates/template.html', "utf-8");
        email = {
            subject: `Subject`,
            text: `Text`
        };
    }

    let info = await transporter.sendMail({
        from: `"NAME" <${testing ? 'testing@test.com' : process.env.SMTP_USERNAME}>`,
        to: data.email,
        subject: email.subject,
        text: email.text,
        html: content,
    });

    // // Preview only available in testing
    if (testing) console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

    return info.messageId ? true : false;
};

const setTestingAccount = async () => {
    let testAccount = await nodemailer.createTestAccount();
    let transporter = nodemailer.createTransport({
        host: "smtp.ethereal.email",
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
            user: testAccount.user,
            pass: testAccount.pass,
        },
    });
    return transporter;
}

const setSMTPAccount = async () => {
    let transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_PORT === '465' ? true : false,
        auth: {
            user: process.env.SMTP_USERNAME,
            pass: process.env.SMTP_PASSWORD,
        }
    });
    return transporter;
}

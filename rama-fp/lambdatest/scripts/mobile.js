
const {_android} = require("playwright");

async function test(deviceName, platformVersion) {
    const capabilities = {
        "LT:Options": {
            "platformName": "android",
            "deviceName": deviceName,
            "platformVersion": platformVersion,
            "isRealMobile": true,
            "build": `Playwright android build ${deviceName} ${platformVersion}`,
            "name": `Playwright android test ${deviceName} ${platformVersion}`,
            "user": process.env.LT_USERNAME,
            "accessKey": process.env.LT_ACCESS_KEY,
            "network": true,
            "video": true,
            "console": true,
            "projectName": "rama-fp",
        },
    };

    let device = await _android.connect(
        `wss://cdp.lambdatest.com/playwright?capabilities=${encodeURIComponent(
            JSON.stringify(capabilities))}`,
    );

    console.log(`Model:: ${device.model()}, serial:: ${device.serial()}`);

    await device.shell("am force-stop com.android.chrome");

    let context = await device.launchBrowser();

    const urls = [
        "http://fp.ramaproxy.org:80/",
        "https://fp.ramaproxy.org:443/",
        "http://h1.fp.ramaproxy.org:80/",
        "https://h1.fp.ramaproxy.org:443/",
    ];

    for (let url of urls) {
        let page = await context.newPage();
        console.log("Navigating to:: ", url);
        await page.goto(url);
        console.log(await page.evaluate('() => document.location.href'));

        await page.$('a[href="/report"]').then((el) => el.click());
        console.log(await page.evaluate('() => document.location.href'));

        await page.$('button[type="submit"]').then((el) => el.click());
        console.log(await page.evaluate('() => document.location.href'));

        await page.$('button[type="submit"]').then((el) => el.click());
        console.log(await page.evaluate('() => document.location.href'));

        await page.close();
    }

    await context.close();
    await device.close();
}

(async () => {
    const devices = [
        {deviceName: "Galaxy S24", platformVersion: "14"},
        {deviceName: "Pixel 6", platformVersion: "14"},
        {deviceName: "Pixel 7", platformVersion: "14"},
        {deviceName: "Pixel 8", platformVersion: "14"},
        {deviceName: "OnePlus 11", platformVersion: "13"},
        {deviceName: "OnePlus 11", platformVersion: "14"},
        {deviceName: "Huawei P50 Pro", platformVersion: "11"},
    ];

    for (let device of devices) {
        console.log("Testing:: ", device.deviceName, device.platformVersion)
        await test(device.deviceName, device.platformVersion);
    }
})();

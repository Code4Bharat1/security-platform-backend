import Tesseract from "tesseract.js"
import sharp from 'sharp';

var titleValue = {}
var messages = [];
var score = 0
var imageBuffer = ""

const privacyViewTitleTexts = ["who can see my personal info", "last seen and online", "profile picture", "about", "links", "status", "read receipts", "disappearing messages", "default message timer", "groups", "avatar stickers", "live location", "calls", "contacts", "app lock", "chat lock", "allow camera effects", "privacy checkup"]
const privacyViewTitleNeededTexts = ["last seen and online", "profile picture", "about", "links", "status", "read receipts", "default message timer", "groups", "avatar stickers", "app lock", "allow camera effects"]
const advancedViewTitleTexts = ["block unknown accound messages", "protect ip address in call", "disable link previews"]

async function containsGreen(yStart = 0, yEnd = null) {
    const image = sharp(imageBuffer);
    const metadata = await image.metadata();

    const imgWidth = metadata.width;
    const imgHeight = metadata.height;

    yEnd = yEnd === null ? imgHeight : Math.min(yEnd, imgHeight);
    yStart = Math.max(0, yStart);

    const left = Math.floor(imgWidth / 2);
    const top = yStart;
    const extractWidth = imgWidth - left;
    const extractHeight = yEnd - yStart;

    if (extractHeight <= 0 || extractWidth <= 0) {
        return false;
    }

    const rawBuffer = await image
        .removeAlpha()
        .extract({ left, top, width: extractWidth, height: extractHeight })
        .raw()
        .toBuffer();

    const channels = 3; // RGB

    for (let i = 0; i < rawBuffer.length; i += channels) {
        const r = rawBuffer[i];
        const g = rawBuffer[i + 1];
        const b = rawBuffer[i + 2];

        // Visible green detection logic
        const avg = (r + g + b) / 3;
        const isGreenDominant = g > r + 25 && g > b + 25;
        const isBrightEnough = avg > 50;
        const isNotGray = Math.abs(r - g) > 15 || Math.abs(b - g) > 15;

        if (g > 60 && isGreenDominant && isBrightEnough && isNotGray) {
            console.log(`Green pixel found: R=${r}, G=${g}, B=${b}`);
            return true;
        }
    }

    return false;
}

async function ratePrivacyView(lines, linesWithPos) {
    let currentTitle = "";

    for (const line of lines) {
        if (line.startsWith("allow camera effects")) currentTitle = "allow camera effects";

        if (privacyViewTitleTexts.includes(line)) {
            currentTitle = line;
            continue;
        }

        if (!privacyViewTitleNeededTexts.includes(currentTitle)) continue;

        if (currentTitle.endsWith("read receipts") || currentTitle.endsWith("allow camera effects")) {
            if (titleValue[currentTitle]) continue;

            const endsWithValue = currentTitle.includes("read receipts") ? "read" : "allow";
            let tsvData = linesWithPos.filter((value) => value.endsWith(endsWithValue));
            tsvData = tsvData.map((value) => value.split("\t"));

            const readTextPos = [
                Math.round(parseInt(tsvData[0][7], 10)) - 10,
                Math.round(parseInt(tsvData[0][9], 10)) + Math.round(parseInt(tsvData[0][7], 10)) + 10
            ];

            titleValue[currentTitle] = await containsGreen(readTextPos[0], readTextPos[1]) ? "on" : "off";
            currentTitle = "";
            continue;
        } else if (currentTitle === "default message timer") {
            for (const value of ["24 hours", "7 days", "90 days", "off"]) {
                if (line.includes(value)) {
                    titleValue[currentTitle] = value;
                    break;
                }
            }
            continue;
        }

        titleValue[currentTitle] = line.includes(",") ? line.replace(" ", "").split(",") : line;
    }

    Object.keys(titleValue).forEach((value) => {
        if (value.includes("last seen and online")) {
            let local_score = 0;

            if (!Array.isArray(titleValue[value]) && !titleValue[value].includes("everyone")) {
                local_score += 1;
                messages.push(`Last Seen & Online: Limited visibility improves privacy. (+1)`);
            }

            if (titleValue[value] === "nobody") {
                local_score += 1;
                messages.push(`Last Seen & Online: Set to 'nobody', maximizing privacy. (+1)`);
            }

            if (!local_score) messages.push(`Last Seen & Online: Visible to everyone. Low privacy. (+0)`);

            score += local_score;
        }

        if (value.includes("profile picture") || value.includes("about") || value.includes("links")) {
            let points = 0;
            if (titleValue[value] === "nobody") {
                points = 2;
                messages.push(`${value}: Hidden from everyone, great for privacy. (+${points})`);
            } else if (titleValue[value] === "my contacts") {
                points = 1;
                messages.push(`${value}: Visible only to contacts. Moderate privacy. (+${points})`);
            } else if (titleValue[value].endsWith("excluded")) {
                points = 1;
                messages.push(`${value}: Visible to contacts except selected people. Reasonable privacy. (+${points})`);
            } else if (titleValue[value] === "everyone") {
                points = 0;
                messages.push(`${value}: Visible to everyone. Low privacy. (+${points})`);
            } else {
                messages.push(`${value}: Invalid value.`);
            }
            score += points;
        }

        if (value.includes("status")) {
            let points = 0;
            if (titleValue[value].endsWith("selected")) {
                points = 2;
                messages.push(`Status: Shared with selected people only. High privacy. (+${points})`);
            } else if (titleValue[value].includes("contact")) {
                points = 1;
                messages.push(`Status: Shared with contacts. Moderate privacy. (+${points})`);
            } else {
                messages.push("Status: Invalid or public setting. Check configuration.");
            }
            score += points;
        }

        if (value.includes("read receipts")) {
            let points = 0;
            if (titleValue[value] === "on") {
                points = 1;
                messages.push(`Read Receipts: Enabled. Others can see when you read messages. (+${points})`);
            } else if (titleValue[value] === "off") {
                points = 0;
                messages.push(`Read Receipts: Disabled. More privacy. (+${points})`);
            } else {
                messages.push("Read Receipts: Invalid setting.");
            }
            score += points;
        }

        if (value.includes("default message timer")) {
            let points = 0;
            const val = titleValue[value];
            if (val === "24 hours") points = 3;
            else if (val === "7 days") points = 2;
            else if (val === "90 days") points = 1;
            else if (val === "off") points = 0;
            else messages.push("Message Timer: Invalid setting.");

            if (typeof points === "number")
                messages.push(`Message Timer: ${val}. ${points > 0 ? "Good" : "Poor"} privacy. (+${points})`);
            score += points;
        }

        if (value.includes("groups")) {
            let points = 0;
            if (titleValue[value] === "my contacts") {
                points = 2;
                messages.push(`Groups: Only contacts can add you. Good privacy. (+${points})`);
            } else if (titleValue[value].endsWith("excluded")) {
                points = 2;
                messages.push(`Groups: Contacts except selected people. Still private. (+${points})`);
            } else if (titleValue[value] === "everyone") {
                points = 0;
                messages.push(`Groups: Anyone can add you. Low privacy. (+${points})`);
            } else {
                messages.push("Groups: Invalid value.");
            }
            score += points;
        }

        if (value.includes("avatar stickers")) {
            let points = 0;
            if (titleValue[value] === "nobody") {
                points = 2;
                messages.push(`Avatar Stickers: Hidden from everyone. High privacy. (+${points})`);
            } else if (titleValue[value] === "my contacts") {
                points = 1;
                messages.push(`Avatar Stickers: Visible only to contacts. Medium privacy. (+${points})`);
            } else if (titleValue[value].endsWith("selected")) {
                points = 1;
                messages.push(`Avatar Stickers: Visible to selected contacts. Medium privacy. (+${points})`);
            } else {
                messages.push("Avatar Stickers: Invalid setting.");
            }
            score += points;
        }

        if (value.includes("app lock")) {
            let points = 0;
            if (titleValue[value] === "enabled") {
                points = 2;
                messages.push(`App Lock: Enabled. Enhances device-level security. (+${points})`);
            } else if (titleValue[value] === "disabled") {
                points = 0;
                messages.push(`App Lock: Disabled. Anyone with access to your phone can read chats. (+${points})`);
            } else {
                messages.push("App Lock: Invalid value.");
            }
            score += points;
        }
    });

    console.log("Privacy Score:", score);
    messages.forEach((msg) => console.log(msg));
}

async function rateAdvancedView(linesWithPos) {
    let currentTitle = "";

    let tsvData = linesWithPos.filter((value, index) =>
        (value.endsWith("block") && linesWithPos[index + 1]?.endsWith("unknown")) ||
        (value.endsWith("protect") && linesWithPos[index + 1]?.endsWith("ip")) ||
        (value.endsWith("disable") && linesWithPos[index + 1]?.endsWith("link"))
    );

    tsvData = tsvData.map((value) => value.split("\t"));

    for (const value of tsvData) {
        if (value.includes("block")) currentTitle = advancedViewTitleTexts[0];
        else if (value.includes("protect")) currentTitle = advancedViewTitleTexts[1];
        else currentTitle = advancedViewTitleTexts[2];

        let readTextPos = [
            Math.round(parseInt(value[7], 10)) - 10,
            Math.round(parseInt(value[9], 10)) + Math.round(parseInt(value[7], 10)) + 10
        ];

        titleValue[currentTitle] = await containsGreen(readTextPos[0], readTextPos[1]) ? "on" : "off";
    }

    Object.keys(titleValue).forEach((value) => {
        if (advancedViewTitleTexts.some((key) => value.includes(key))) {
            let points = 0;
            if (titleValue[value] === "on") {
                points = 2;
                messages.push(`${value}: Enabled. Adds extra privacy and security. (+${points})`);
            } else if (titleValue[value] === "off") {
                points = 0;
                messages.push(`${value}: Disabled. Less privacy protection. (+${points})`);
            } else {
                messages.push(`${value}: Invalid setting.`);
            }
            score += points;
        }
    });

    console.log("Advanced Privacy Score:", score);
    messages.forEach((msg) => console.log(msg));
}

const whatsappPrivacyInspectorController = async (req, res) => {
    
    const images = [req.files.image1[0], req.files.image2[0]]

    for (const image in images) {
        imageBuffer = await sharp(image).toBuffer();
        const worker = await Tesseract.createWorker('eng');

        let recognizedDataText = ""
        let recognizedDataTSV = ""
        try {
            const { data } = await worker.recognize(imageBuffer, {}, { tsv: 1 });

            recognizedDataText = data.text.replace(/[^a-zA-Z0-9\n\s]/g, '').split("\n").filter((value) => value != '')
            recognizedDataText = recognizedDataText.map((value) => value.trim().toLowerCase())
            recognizedDataTSV = data.tsv.split("\n")
            recognizedDataTSV = recognizedDataTSV.map((value) => value.trim().toLowerCase())

            if (recognizedDataText.filter((value) => value.endsWith("privacy")).length) {
                view = "privacy"
                ratePrivacyView(recognizedDataText, recognizedDataTSV)
            } else if (recognizedDataText.filter((value) => value.endsWith("advanced")).length) {
                view = "advanced"
                rateAdvancedView(recognizedDataTSV)
            } else {
                view = "invalid"
                throw new Error("Please enter proper whatsapp privacy and advance page image.");
            }
            res.status(200).json({score: score, messages: messages});
        } catch (err) {
            console.log('OCR failed for one of the images.', err);
        }
        titleValue = {}
        message = []
        score = 0
        var imageBuffer = ""

        await worker.terminate();
    }
}

export default whatsappPrivacyInspectorController;
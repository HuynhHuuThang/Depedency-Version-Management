// import express from "express";
// var app = express();

// var server = app.listen(3000, function(){
//     console.log("Node.js is listening to PORT:" + server.address().port);
// });

// var photoList = [
//     {
//         id: "1",
//         name: "photo001.jpg",
//         type: "jpg",
//         dataUrl: "http://localhost:3000/data/photo001.jpg"
//     },{
//         id: "2",
//         name: "photo002.jpg",
//         type: "jpg",
//         dataUrl: "http://localhost:3000/data/photo002.jpg"
//     }
// ]
// const logger = function(req, res, next){
//     if (req.url === "/api/photo/1"){
//         res.send("photo1")
//     }
//     else{
//         next()
//     }
    
// }

// app.use(logger)
// app.get("/api/photo/:photoId", function(req, res, next){
//     var photo;
//     let i = 0;
//     for (i = 0; i < photoList.length; i++){
//         if (photoList[i].id == req.params.photoId){
//             var photo = photoList[i];
//         }
//     }
//     res.json(photo);
// });


import axios from "axios";
import {writeFileSync} from "fs";
import https from 'https';


async function getNpmPackageInfo(packageName) {
    try {
        const response = await axios.get(`https://registry.npmjs.org/${packageName}`);
        const data = response.data;
        const latestVersion = data['dist-tags'].latest;
        const publishDate = data.time[latestVersion];

        console.log(`Package: ${packageName}`);
        console.log(`Latest Version: ${latestVersion}`);
        console.log(`Latest Published: ${new Date(publishDate).toLocaleDateString()}`);
        return publishDate;
    } catch (error) {
        console.error('Error fetching package info:', error.message);
    }
}

async function getPullRequestsCount(repoUrl) {
    try {
        // Extract the owner and repo name from the URL
        const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
        if (!match) throw new Error('Invalid GitHub repository URL');

        const owner = match[1];
        const repo = match[2];
        const response = await axios.get(`https://api.github.com/repos/${owner}/${repo}/pulls`);
        return response.data.length;
    } catch (error) {
        console.error('Error fetching pull requests:', error.message);
        return 0; // Return 0 if there's an error
    }
}

async function downloadsCount(packageName, fromDate, untilDate) {
    try {
        const response = await axios.get(
            `https://api.npmjs.org/downloads/point/${fromDate}:${untilDate}/${packageName}`,
            {
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            }
        );
        return response.data.downloads;
    } catch (error) {
        console.error('Error fetching download counts:', error.message);
        return 0;
    }
}

async function downloadsCountPerVersion(packageName, version) {
    try {
        const response = await axios.get(
            `https://api.npmjs.org/versions/${packageName}/last-week`,
            {
                httpsAgent: new https.Agent({ rejectUnauthorized: false })
            }
        );
        console.log(response.data.downloads[version]);
        return response.data.downloads[version];
    } catch (error) {
        console.error('Error fetching download counts:', error.message);
        return 0;
    }
}
async function isPackageBeingMaintained(packageName) {
    const latestPublishDate = await getNpmPackageInfo(packageName);
    const now = new Date();
    const latestPublishDateObj = new Date(latestPublishDate);
    console.log(latestPublishDateObj);
    const diffTime = Math.abs(now - latestPublishDateObj);
    console.log(diffTime);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
    console.log(diffDays);
    return diffDays <= 180;
}


const fromDate = "2024-11-20";
const unitDate = "2024-11-20";
const data = await getNpmPackageInfo('lodash',fromDate,unitDate);
const downloads = await downloadsCount('lodash', fromDate, unitDate);
console.log(downloads);
const downloadsPerVersion = await downloadsCountPerVersion('lodash', '4.0.0');
console.log(downloadsPerVersion);
const isMaintained = await isPackageBeingMaintained('lodash');
console.log(isMaintained);
writeFileSync('result.json', JSON.stringify(data,null,2));
console.log("save to file");

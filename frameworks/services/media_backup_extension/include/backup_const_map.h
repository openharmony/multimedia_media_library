/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MEDIA_BACKUP_CONST_MAP_H
#define OHOS_MEDIA_BACKUP_CONST_MAP_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace Media {
const int CHAR_FIRST_NUMBER = 72;
const int CHAR_SECOND_NUMBER = 117;
const int CHAR_THIRD_NUMBER = 97;
const int CHAR_FOURTH_NUMBER = 119;
const int CHAR_FIFTH_NUMBER = 101;
const int CHAR_SIXTH_NUMBER = 105;

static std::string GetDUALBundleName(bool bLower = false)
{
    int arr[] = { CHAR_FIRST_NUMBER, CHAR_SECOND_NUMBER, CHAR_THIRD_NUMBER, CHAR_FOURTH_NUMBER, CHAR_FIFTH_NUMBER,
        CHAR_SIXTH_NUMBER };
    int len = sizeof(arr) / sizeof(arr[0]);
    std::string dualBundleName = "";
    for (int i = 0; i < len; i++) {
        dualBundleName += char(arr[i]);
    }
    if (bLower) {
        transform(dualBundleName.begin(), dualBundleName.end(), dualBundleName.begin(), ::tolower);
    }
    return dualBundleName;
}

const std::string SCREEN_SHOT_AND_RECORDER = "截屏录屏";
const std::string VIDEO_SCREEN_RECORDER_NAME = "屏幕录制";
const std::string VIDEO_SCREEN_RECORDER = "com."+ GetDUALBundleName(true) +".ohos.screenrecorder";

static inline const std::unordered_map<std::string, std::pair<std::string, std::string>> ALBUM_PART_MAP = {
    {"/", {"根目录", "rootdirectory"}},
    {"/DCIM/Camera", {"相机", "Camera"}},
    {"/Pictures/Screenshots", {"截屏录屏", "Screenshots"}},
    {"/download", {"已下载", "Downloads"}},
    {"/Imported", {"已导入", "Imported"}},
    {"/" + GetDUALBundleName() +"/MagazineUnlock", {"杂志锁屏", "MagazineUnlock"}},
    {"/EditedOnlinePhotos", {"编辑过的在线照片", "Editedonlinephotos"}},
    {"/CloudPicture", {"下载中心", "Downloads"}},
    {"/tencent/QQ_Images", {"QQ", "QQImages"}},
    {"/tencent/QQ_Favorite", {"QQ表情", "QQFavorite"}},
    {"/tencent/QzonePic", {"QQ空间", "Qzone"}},
    {"/tencent/MicroMsg/WeiXin", {"微信", "WeChat"}},
    {"/tencent/MicroMsg/WeChat", {"微信", "WeChat"}},
    {"/Pictures/WeiXin", {"微信", "WeChat"}},
    {"/Pictures/WeChat", {"微信", "WeChat"}},
    {"/sina/weibo/save", {"微博", "Weibo"}},
    {"/sina/weibo/weibo", {"微博", "Weibo"}},
    {"/Pictures/weibo", {"微博", "Weibo"}},
    {"/sina/weibo/storage/photoalbum_save/weibo", {"微博", "Weibo"}},
    {"/taobao", {"淘宝", "taobao"}},
    {"/Pictures/taobao", {"淘宝", "taobao"}},
    {"/UCDownloads", {"UC下载", "UCDownloads"}},
    {"/QIYIVideo", {"爱奇艺视频", "QIYIVideo"}},
    {"/dianping", {"大众点评", "dianping"}},
    {"/MTXX", {"美图秀秀", "MTXX"}},
    {"/Photowonder", {"百度魔图", "Photowonder"}},
    {"/MYXJ", {"美颜相机", "MYXJ"}},
    {"/Pictures/InstaMag", {"拼立得", "InstaMag"}},
    {"/MTTT", {"美图贴贴", "MTTT"}},
    {"/MomanCamera", {"魔漫相机", "MomanCamera"}},
    {"/Bluetooth", {"蓝牙分享", "Bluetooth"}},
    {"/ShareViaWLAN", {"WLAN分享", "ShareViaWLAN"}},
    {"/Pictures", {"图片", "Pictures"}},
    {"/Video", {"视频", "Videos"}},
    {"/DCIM/GroupRecorder", {"大导演", "DirectorMode"}},
    {"/Pictures/Recover", {"恢复", "Restore"}},
    {"/baidu/searchbox/downloads", {"手机百度", "downloads"}},
    {"/Pictures/meituan", {"美团", "meituan"}},
    {"/DCIM/jdimage", {"京东", "jdimage"}},
    {"/funnygallery", {"今日头条", "funnygallery"}},
    {"/Pictures/ifeng/download_pic", {"凤凰新闻", "download_pic"}},
    {"/UCDownloads/pictures", {"UC浏览器", "pictures"}},
    {"/QQMail", {"QQ邮箱", "QQMail"}},
    {"/tieba", {"百度贴吧", "tieba"}},
    {"sina/news/save", {"新浪新闻", "save"}},
    {"/DCIM/Camera/miaopai", {"秒拍", "miaopai"}},
    {"Pictures/ButterCamera", {"黄油相机", "ButterCamera"}},
    {"/DCIM/1Videoshow", {"乐秀视频", "1Videoshow"}},
    {"/Pictures/Cooper", {"库柏", "AIVideo"}},
    {"/Pictures/VideoEditor", {"视频编辑", "VideoEditor"}},
    {"/Pictures/Collage", {"拼图", "Collages"}},
    {"//Pictures/FromOtherDevices", {"其他设备保存", "Fromotherdevices"}},
    {"/" + GetDUALBundleName() +"/preset", {"预置图片", "Presetimages"}},
    {"/" + GetDUALBundleName() +" Share", {"华为分享", GetDUALBundleName() +"Share"}},
    {"/Pictures/Meetime", {"畅连", "MeeTime"}},
    {"/Pictures/DoodleBoard", {"白板", "DoodleBoard"}},
    {"/Pictures/Annotation", {"批注", "Annotations"}},
    {"/Pictures/douyin", {"抖音", "douyin"}},
};

static inline const std::unordered_map<std::string, std::pair<std::string, std::string>> ALBUM_WHITE_LIST_MAP = {
    {"相机", {"相机", "com."+ GetDUALBundleName(true) +".hmos.camera"}},
    {"华为分享", {"华为分享", "com."+ GetDUALBundleName(true) +".hmos.instantshare"}},
    {"截屏录屏", {"截图", "com."+ GetDUALBundleName(true) +".ohos.screenshot"}},
    {"小红书", {"小红书", "com.xingxi.xhs_hos"}},
    {"微博", {"微博", "com.sina.weibo.stage"}},
    {"搜狐新闻", {"搜狐新闻", "com.sohu.harmonynews"}},
    {"新浪新闻", {"新浪新闻", "com.sina.news.hm.next"}},
    {"抖音", {"抖音", "com.ss.hm.ugc.aweme"}},
    {"下厨房", {"下厨房", "com.xiachufang.recipe"}},
    {"唯品会", {"唯品会", "com.vip.hosapp"}},
};
} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIA_BACKUP_CONST_MAP_H

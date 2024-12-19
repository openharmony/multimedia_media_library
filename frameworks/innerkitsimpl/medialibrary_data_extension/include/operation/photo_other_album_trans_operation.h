/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PHOTO_OTHER_ALBUM_TRANS_OPERATIOIN_H
#define OHOS_MEDIA_PHOTO_OTHER_ALBUM_TRANS_OPERATIOIN_H

#include <string>

#include "medialibrary_rdb_store.h"

namespace OHOS::Media {
class PhotoOtherAlbumTransOperation {
public:
    static PhotoOtherAlbumTransOperation &GetInstance();
    int32_t TransOtherAlbumData(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore, bool &isNeedUpdate);
    PhotoOtherAlbumTransOperation &Start();
    void Stop();

private:
    void BuildOtherAlbumInsertValuesIfNeed(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
        const string &albumName, const string &lpath, const string &bundleName,
        std::vector<std::pair<int64_t, std::string>> &transAlbum);
    bool CheckIfNeedTransOtherAlbumData(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
        int64_t otherAlbumId, std::vector<std::pair<int64_t, std::string>> &transAlbum);
    int32_t DealWithOtherAlbumTrans(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
        std::pair<int64_t, std::string> transInfo, int64_t otherAlbumId);
    bool IsOtherAlbumEmpty(const int64_t &otherAlbumId, const std::shared_ptr<MediaLibraryRdbStore> upgradeStore);
    void GetOtherAlbumIdInfo(const std::shared_ptr<MediaLibraryRdbStore> upgradeStore,
        int64_t &otherAlbumId, std::vector<std::pair<int64_t, std::string>> &transAlbum);

private:
    private:
    std::atomic<bool> isContinue_{true};
    static std::shared_ptr<PhotoOtherAlbumTransOperation> instance_;
    static std::mutex objMutex_;

private:
    const std::string OTHER_ALBUM_NAME = "其它";
    const std::string SCREENSHOT_ALBUM_NAME = "截图";
    const std::string SCREENRECORD_ALBUM_NAME = "屏幕录制";
    const std::string WECHAT_ALBUM_NAME = "微信";
    const std::string ALBUM_NAME_CAMERA = "相机";
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTO_OTHER_ALBUM_TRANS_OPERATIOIN_H

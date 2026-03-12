/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_VIDEO_RINGTONE_PROCESSOR_H
#define OHOS_MEDIA_VIDEO_RINGTONE_PROCESSOR_H

#include "datashare_helper.h"
#include "rdb_store.h"

namespace OHOS {
namespace Media {

class VideoRingtoneProcessor {
public:
    VideoRingtoneProcessor() = default;
    ~VideoRingtoneProcessor();

    void ProcessVideoRingtones(std::shared_ptr<NativeRdb::RdbStore> &rdbStore);

private:
    VideoRingtoneProcessor(const VideoRingtoneProcessor&) = delete;
    VideoRingtoneProcessor& operator=(const VideoRingtoneProcessor&) = delete;

    bool GetActiveUserId();
    int32_t InitDataShareHelper();
    std::string QueryMp4RingtonePath(const std::string& key);
    bool IsMp4VideoFile(const std::string& path);
    int32_t ConvertOldUriToNewUri(const std::string& oldUri, std::string& newUri);
    void SetVideoFilePermission(const std::string& oldUri);
    int32_t GetAppIdAndTokenId(const std::string &bundleName, int32_t userId,
        std::string &appId, uint32_t &tokenId);
    std::string GetUrisByOldUrisInner(const std::string &oldUris, int32_t &mediaId);
    int32_t SetPermissionForFile(const std::string& appId, uint32_t tokenId, int32_t mediaId);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    std::string settingsDataUri_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    int32_t userId_ = -1;
};

} // namespace Media
} // namespace OHOS

#endif // OHOS_MEDIA_VIDEO_RINGTONE_PROCESSOR_H

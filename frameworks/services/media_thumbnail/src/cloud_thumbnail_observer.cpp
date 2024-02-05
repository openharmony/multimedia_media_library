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

#include "cloud_thumbnail_observer.h"
#include "medialibrary_rdb_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {

static inline bool isFileIdValid(const std::string& fileId)
{
    for (char const& ch : fileId) {
        if (std::isdigit(ch) == 0) {
            return false;
        }
    }
    return true;
}

void CloudThumbnailObserver::OnChange(const ChangeInfo &changeInfo)
{
    MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    if (changeInfo.changeType_ != ChangeType::INSERT) {
        MEDIA_DEBUG_LOG("change type is %{public}d, not insert", changeInfo.changeType_);
        return;
    }
    for (auto &uri : changeInfo.uris_) {
        string uriString = uri.ToString();
        auto pos = uriString.find_last_of('/');
        if (pos == std::string::npos) {
            continue;
        }
        string idString = uriString.substr(pos + 1);
        if (idString.empty() || !isFileIdValid(idString)) {
            MEDIA_DEBUG_LOG("cloud observer get no valid fileId and uri : %{public}s", uriString.c_str());
            continue;
        }
        ThumbnailService::GetInstance()->CreateAstcFromFileId(idString);
    }
}
} // namespace Media
} // namespace OHOS
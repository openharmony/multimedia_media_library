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

#include "cloud_sync_notify_handler.h"

#include "notify_responsibility_chain_factory.h"
#include "thumbnail_service.h"
#include "medialibrary_rdb_utils.h"
#include "photo_album_column.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {
using ChangeType = DataShare::DataShareObserver::ChangeType;

static inline bool IsFileIdValid(const string& fileId)
{
    for (char const& ch : fileId) {
        if (isdigit(ch) == 0) {
            return false;
        }
    }
    return true;
}

void CloudSyncNotifyHandler::ThumbNailObserverOnchange(const list<Uri> &uris, const ChangeType &type)
{
    MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    if (type != ChangeType::INSERT) {
        MEDIA_DEBUG_LOG("change type is %{public}d, not insert", type);
        return;
    }
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto pos = uriString.find_last_of('/');
        if (pos == string::npos) {
            continue;
        }
        string idString = uriString.substr(pos + 1);
        if (idString.empty() || !IsFileIdValid(idString)) {
            MEDIA_DEBUG_LOG("cloud observer get no valid fileId and uri : %{public}s", uriString.c_str());
            continue;
        }
        ThumbnailService::GetInstance()->CreateAstcFromFileId(idString);
    }
}

void CloudSyncNotifyHandler::MakeResponsibilityChain()
{
    string uriString = notifyInfo_.uris.front().ToString();
    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos) {
        ThumbNailObserverOnchange(notifyInfo_.uris, notifyInfo_.type);
    }

    shared_ptr<BaseHandler> chain = nullptr;
 
    if (uriString.find(PhotoAlbumColumns::ALBUM_CLOUD_URI_PREFIX) != string::npos) {
        chain = NotifyResponsibilityChainFactory::CreateChain(TRANSPARENT);
    }
 
    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos) {
        if (notifyInfo_.type == ChangeType::UPDATE || notifyInfo_.type == ChangeType::OTHER) {
            chain = NotifyResponsibilityChainFactory::CreateChain(PHOTODELETE);
        } else {
            chain = NotifyResponsibilityChainFactory::CreateChain(TRANSPARENT);
        }
    }
    CloudSyncHandleData handleData;
    handleData.orgInfo = notifyInfo_;
    chain->Handle(handleData);
    return;
}
} //namespace Media
} //namespace OHOS

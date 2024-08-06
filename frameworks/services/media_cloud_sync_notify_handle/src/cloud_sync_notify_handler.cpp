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

static inline bool IsCloudNotifyInfoValid(const string& cloudNotifyInfo)
{
    if (cloudNotifyInfo.empty() || cloudNotifyInfo == "0") {
        return false;
    }
    for (char const& ch : cloudNotifyInfo) {
        if (isdigit(ch) == 0) {
            return false;
        }
    }
    return true;
}

void CloudSyncNotifyHandler::HandleInsertEvent(const std::list<Uri> &uris)
{
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto pos = uriString.find_last_of('/');
        if (pos == string::npos) {
            continue;
        }
        string idString = uriString.substr(pos + 1);
        if (!IsCloudNotifyInfoValid(idString)) {
            MEDIA_WARN_LOG("cloud observer get no valid fileId and uri : %{public}s", uriString.c_str());
            continue;
        }

        ThumbnailService::GetInstance()->CreateAstcCloudDownload(idString);
    }
}

void CloudSyncNotifyHandler::HandleDeleteEvent(const std::list<Uri> &uris)
{
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto dateAddedPos = uriString.rfind('/');
        if (dateAddedPos == string::npos) {
            continue;
        }
        auto fileIdPos = uriString.rfind('/', dateAddedPos - 1);
        if (fileIdPos == string::npos) {
            continue;
        }

        string dateAdded = uriString.substr(dateAddedPos + 1);
        string fileId = uriString.substr(fileIdPos + 1, dateAddedPos - fileIdPos - 1);
        if (!IsCloudNotifyInfoValid(dateAdded) || !IsCloudNotifyInfoValid(fileId)) {
            MEDIA_WARN_LOG("cloud observer get no valid uri : %{public}s", uriString.c_str());
            continue;
        }

        ThumbnailService::GetInstance()->DeleteAstcWithFileIdAndDateAdded(fileId, dateAdded);
    }
}

void CloudSyncNotifyHandler::HandleTimeUpdateEvent(const std::list<Uri> &uris)
{
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto newDateAddedPos = uriString.rfind('/');
        if (newDateAddedPos == string::npos) {
            continue;
        }
        auto formerDateAddedPos = uriString.rfind('/', newDateAddedPos - 1);
        if (formerDateAddedPos == string::npos) {
            continue;
        }
        auto fileIdPos = uriString.rfind('/', formerDateAddedPos - 1);
        if (fileIdPos == string::npos) {
            continue;
        }

        string newDateAdded = uriString.substr(newDateAddedPos + 1);
        string formerDateAdded = uriString.substr(formerDateAddedPos + 1, newDateAddedPos - formerDateAddedPos - 1);
        string fileId = uriString.substr(fileIdPos + 1, formerDateAddedPos - fileIdPos - 1);
        if (!IsCloudNotifyInfoValid(newDateAdded) || !IsCloudNotifyInfoValid(formerDateAdded) ||
            !IsCloudNotifyInfoValid(fileId)) {
            MEDIA_WARN_LOG("cloud observer get no valid uri : %{public}s", uriString.c_str());
            continue;
        }

        ThumbnailService::GetInstance()->UpdateAstcWithNewDateAdded(fileId, newDateAdded, formerDateAdded);
    }
}

void CloudSyncNotifyHandler::HandleExtraEvent(const std::list<Uri> &uris, const ChangeType &type)
{
    ExtraChangeType extraType = static_cast<ExtraChangeType>(type);
    if (extraType == ExtraChangeType::PHOTO_TIME_UPDATE) {
        HandleTimeUpdateEvent(uris);
        return;
    }
    MEDIA_DEBUG_LOG("change type is %{public}d, no need ThumbnailObserverOnChange", type);
}

void CloudSyncNotifyHandler::ThumbnailObserverOnChange(const list<Uri> &uris, const ChangeType &type)
{
    MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    switch (type) {
        case ChangeType::INSERT:
            HandleInsertEvent(uris);
            break;
        case ChangeType::DELETE:
            HandleDeleteEvent(uris);
            break;
        default:
            HandleExtraEvent(uris, type);
            break;
    }
}

void CloudSyncNotifyHandler::MakeResponsibilityChain()
{
    string uriString = notifyInfo_.uris.front().ToString();
    MEDIA_DEBUG_LOG("observer get first uri is : %{public}s", uriString.c_str());

    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos) {
        ThumbnailObserverOnChange(notifyInfo_.uris, notifyInfo_.type);
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
    if (chain == nullptr) {
        MEDIA_ERR_LOG("uri OR type is Invalid");
        return;
    }
    chain->Handle(handleData);
}
} //namespace Media
} //namespace OHOS

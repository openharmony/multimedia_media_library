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

#include "medialibrary_album_fusion_utils.h"
#include "notify_responsibility_chain_factory.h"
#include "thumbnail_service.h"
#include "medialibrary_rdb_utils.h"
#include "parameters.h"
#include "photo_album_column.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {
using ChangeType = DataShare::DataShareObserver::ChangeType;

const int32_t CLOUD_FIRST_FIVE_HUNDRED = 1;
const int32_t CLOUD_INCREMENT_DOWNLOAD = 2;
const std::string CLOUDSYNC_STATUS_KEY = "persist.kernel.cloudsync.status";

static bool IsCloudInsertTaskPriorityHigh()
{
    int32_t cloudSyncStatus = static_cast<int32_t>(system::GetParameter(CLOUDSYNC_STATUS_KEY, "0").at(0) - '0');
    return cloudSyncStatus == CLOUD_FIRST_FIVE_HUNDRED || cloudSyncStatus == CLOUD_INCREMENT_DOWNLOAD;
}

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
    bool isCloudInsertTaskPriorityHigh = IsCloudInsertTaskPriorityHigh();
    if (!isCloudInsertTaskPriorityHigh && !ThumbnailService::GetInstance()->GetCurrentStatusForTask()) {
        MEDIA_INFO_LOG("current status is not suitable for task");
        return;
    }
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

        ThumbnailService::GetInstance()->CreateAstcCloudDownload(idString, isCloudInsertTaskPriorityHigh);
    }
}

void CloudSyncNotifyHandler::HandleDeleteEvent(const std::list<Uri> &uris)
{
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto dateTakenPos = uriString.rfind('/');
        if (dateTakenPos == string::npos) {
            continue;
        }
        auto fileIdPos = uriString.rfind('/', dateTakenPos - 1);
        if (fileIdPos == string::npos) {
            continue;
        }

        string dateTaken = uriString.substr(dateTakenPos + 1);
        string fileId = uriString.substr(fileIdPos + 1, dateTakenPos - fileIdPos - 1);
        if (!IsCloudNotifyInfoValid(dateTaken) || !IsCloudNotifyInfoValid(fileId)) {
            MEDIA_WARN_LOG("cloud observer get no valid uri : %{public}s", uriString.c_str());
            continue;
        }

        ThumbnailService::GetInstance()->DeleteAstcWithFileIdAndDateTaken(fileId, dateTaken);
    }
}

void CloudSyncNotifyHandler::HandleTimeUpdateEvent(const std::list<Uri> &uris)
{
    for (auto &uri : uris) {
        string uriString = uri.ToString();
        auto newDateTakenPos = uriString.rfind('/');
        if (newDateTakenPos == string::npos) {
            continue;
        }
        auto formerDateTakenPos = uriString.rfind('/', newDateTakenPos - 1);
        if (formerDateTakenPos == string::npos) {
            continue;
        }
        auto fileIdPos = uriString.rfind('/', formerDateTakenPos - 1);
        if (fileIdPos == string::npos) {
            continue;
        }

        string newDateTaken = uriString.substr(newDateTakenPos + 1);
        string formerDateTaken = uriString.substr(formerDateTakenPos + 1, newDateTakenPos - formerDateTakenPos - 1);
        string fileId = uriString.substr(fileIdPos + 1, formerDateTakenPos - fileIdPos - 1);
        if (!IsCloudNotifyInfoValid(newDateTaken) || !IsCloudNotifyInfoValid(formerDateTaken) ||
            !IsCloudNotifyInfoValid(fileId)) {
            MEDIA_WARN_LOG("cloud observer get no valid uri : %{public}s", uriString.c_str());
            continue;
        }

        ThumbnailService::GetInstance()->UpdateAstcWithNewDateTaken(fileId, newDateTaken, formerDateTaken);
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

    if (uriString.find("file://cloudsync/Photo/HeightError/") != string::npos) {
        return;
    }

    if (uriString.find("file://cloudsync/Photo/DownloadSuccessed/") != string::npos) {
        return;
    }

    if (uriString.find(PhotoColumn::PHOTO_CLOUD_URI_PREFIX) != string::npos) {
        ThumbnailObserverOnChange(notifyInfo_.uris, notifyInfo_.type);
    }

    if (uriString.find("file://cloudsync/Photo/RebuildCloudData/") != string::npos) {
        MEDIA_INFO_LOG("Get cloud rebuild cloud data notification : %{public}s",
            "file://cloudsync/Photo/RebuildCloudData/");
        MediaLibraryAlbumFusionUtils::CleanInvalidCloudAlbumAndData();
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

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
#include "cloud_sync_manager.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_utils.h"
#include "medialibrary_tracer.h"

using namespace std;

namespace OHOS {
namespace Media {
using ChangeType = DataShare::DataShareObserver::ChangeType;
using namespace FileManagement::CloudSync;

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

void CloudSyncNotifyHandler::ThumbnailObserverOnChange(const list<Uri> &uris, const ChangeType &type)
{
    MediaLibraryRdbUtils::SetNeedRefreshAlbum(true);
    switch (type) {
        case ChangeType::INSERT:
        case ChangeType::OTHER:
            HandleInsertEvent(uris);
            break;
        case ChangeType::DELETE:
            HandleDeleteEvent(uris);
            break;
        case ChangeType::PHOTO_TIME_UPDATE:
            HandleTimeUpdateEvent(uris);
            break;
        default:
            MEDIA_DEBUG_LOG("change type is %{public}d, no need ThumbnailObserverOnChange", type);
            break;
    }
}

void CloudSyncNotifyHandler::MakeResponsibilityChain()
{
    string uriString = notifyInfo_.uris.front().ToString();
    MEDIA_DEBUG_LOG("observer get first uri is : %{public}s", uriString.c_str());

    if (uriString.find(PhotoColumn::PHOTO_HEIGHT_ERROR_URI_PREFIX) != string::npos) {
        HandleCloudHeightErrorNotify(notifyInfo_.uris);
        return;
    }

    if (uriString.find(PhotoColumn::PHOTO_DOWNLOAD_SUCCEED_URI_PREFIX) != string::npos) {
        HandleCloudDownloadSucceedNotify(notifyInfo_.uris);
        return;
    }

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

void CloudSyncNotifyHandler::HandleCloudHeightErrorNotify(const list<Uri> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("HandleCloudHeightErrorNotify");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore.");
        return;
    }

    auto filePaths = MediaLibraryRdbUtils::GetPhotoPathsByCloudIds(rdbStore, uris,
        PhotoColumn::PHOTO_HEIGHT_ERROR_URI_PREFIX);
    for (auto &filePath : filePaths) {
        int32_t ret = CloudSyncManager::GetInstance().StartDownloadFile(filePath);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("Start download failed! ret = %{public}d, filePath = %{public}s", ret, filePath.c_str());
            continue;
        }
        MEDIA_DEBUG_LOG("Start download success. filePath = %{public}s", filePath.c_str());
    }
    MEDIA_INFO_LOG("Handle cloud height error notify over, uris.size() is %{public}zu", uris.size());
}

void CloudSyncNotifyHandler::HandleCloudDownloadSucceedNotify(const list<Uri> &uris)
{
    MediaLibraryTracer tracer;
    tracer.Start("HandleCloudDownloadSucceedNotify");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw()->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbstore.");
        return;
    }

    auto filePaths = MediaLibraryRdbUtils::GetPhotoPathsByCloudIds(rdbStore, uris,
        PhotoColumn::PHOTO_DOWNLOAD_SUCCEED_URI_PREFIX);
    for (auto &filePath : filePaths) {
        if (!MediaFileUtils::IsFileExists(filePath)) {
            MEDIA_ERR_LOG("File not exist, filePath: %{public}s.", filePath.c_str());
            continue;
        }

        if (MediaLibraryRdbUtils::UpdatePhotoHeightAndWidth(rdbStore, filePath) < 0) {
            MEDIA_ERR_LOG("Failed to update photo height and width, filePath: %{public}s.", filePath.c_str());
            continue;
        }
        MEDIA_DEBUG_LOG("Download cloud photo success. filePath = %{public}s", filePath.c_str());
    }
    MEDIA_INFO_LOG("Handle download cloud photo over, uris.size() is %{public}zu", uris.size());
}
} //namespace Media
} //namespace OHOS

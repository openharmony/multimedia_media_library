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

#include "uri_convert_handler.h"

#include "media_column.h"
#include "photo_album_column.h"

using namespace std;

namespace OHOS {
namespace Media {

using ChangeType = DataShare::DataShareObserver::ChangeType;
unordered_map<ChangeType, NotifyType> NotifyTypeChangeMap = {
    {ChangeType::INSERT, NotifyType::NOTIFY_ADD},
    {ChangeType::UPDATE, NotifyType::NOTIFY_UPDATE},
    {ChangeType::DELETE, NotifyType::NOTIFY_REMOVE},
};

static void AddNewNotify(CloudSyncHandleData &newHandleData,
    const list<Uri> &sendUris, const ChangeType &changeType)
{
    if (sendUris.size() <= 0) {
        return;
    }
    if (changeType == ChangeType::INSERT) {
        return;
    }
    ChangeType sendType = static_cast<ChangeType>(NotifyTypeChangeMap[changeType]);
    if (newHandleData.notifyInfo.find(sendType) == newHandleData.notifyInfo.end()) {
        newHandleData.notifyInfo[sendType] = sendUris;
    } else {
        newHandleData.notifyInfo[sendType].insert(
            newHandleData.notifyInfo[sendType].end(), sendUris.begin(), sendUris.end());
    }
    return;
}

void UriConvertHandler::Handle(const CloudSyncHandleData &handleData)
{
    const string org_uri_prefix = "file://cloudsync/";
    const string new_uri_prefix = "file://media/";
    CloudSyncNotifyInfo newNotifyInfo;
    CloudSyncHandleData newHandleData = handleData;

    if (handleData.orgInfo.type == ChangeType::OTHER) {
        AddNewNotify(newHandleData, { Uri(PhotoColumn::PHOTO_URI_PREFIX) }, ChangeType::DELETE);
        AddNewNotify(newHandleData, { Uri(PhotoAlbumColumns::ALBUM_URI_PREFIX) }, ChangeType::DELETE);
    } else {
        newNotifyInfo.type = handleData.orgInfo.type;
        for (auto &uri : handleData.orgInfo.uris) {
            string uriString = uri.ToString();
            size_t pos = uriString.find(org_uri_prefix);
            Uri newUri = Uri(uriString.replace(pos, org_uri_prefix.length(), new_uri_prefix));
            newNotifyInfo.uris.push_back(newUri);
        }
        AddNewNotify(newHandleData, newNotifyInfo.uris, newNotifyInfo.type);
    }
 
    if (nextHandler_ != nullptr) {
        nextHandler_->Handle(newHandleData);
    }
    return ;
}
} //namespace Media
} //namespace OHOS

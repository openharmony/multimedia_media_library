/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "medialibrary_trigger_manager.h"
#include "media_log.h"

namespace OHOS {
namespace Media {

static std::string GetTriggerKey(const std::string& tableName, MediaLibraryTriggerManager::TriggerType triggerType)
{
    std::string triggerTypeStr = "";
    switch (triggerType) {
        case MediaLibraryTriggerManager::TriggerType::INSERT:
            triggerTypeStr = "INSERT";
            break;
        case MediaLibraryTriggerManager::TriggerType::UPDATE:
            triggerTypeStr = "UPDATE";
            break;
        case MediaLibraryTriggerManager::TriggerType::DELETE:
            triggerTypeStr = "DELETE";
            break;
        default:
            MEDIA_ERR_LOG("invalid triggerType");
            return "";
    }
    return tableName + "#" + triggerTypeStr;
}

MediaLibraryTriggerManager::MediaLibraryTriggerManager()
{
    getTriggersFuncs_[GetTriggerKey(PhotoColumn::PHOTOS_TABLE, TriggerType::INSERT)].push_back(
        []() -> std::shared_ptr<MediaLibraryTriggerBase> {
            return std::make_shared<InsertSourcePhotoCreateSourceAlbumTrigger>();
        });
    getTriggersFuncs_[GetTriggerKey(PhotoColumn::PHOTOS_TABLE, TriggerType::INSERT)].push_back(
        []() -> std::shared_ptr<MediaLibraryTriggerBase> {
            return std::make_shared<InsertPhotoUpdateAlbumBundleNameTrigger>();
        });
}

std::shared_ptr<MediaLibraryTriggerBase> MediaLibraryTriggerManager::GetTrigger(
    const std::string &table, TriggerType triggerType)
{
    std::shared_ptr<MediaLibraryTrigger> mediaLibraryTrigger = std::make_shared<MediaLibraryTrigger>();
    std::string triggerKey = GetTriggerKey(table, triggerType);
    if (!getTriggersFuncs_.count(triggerKey)) {
        MEDIA_INFO_LOG("there is no trigger for key: %{public}s", triggerKey.c_str());
        return mediaLibraryTrigger;
    }
    std::vector<std::shared_ptr<MediaLibraryTriggerBase> > triggers;
    for (auto getTriggerFunc : getTriggersFuncs_[triggerKey]) {
        triggers.push_back(getTriggerFunc());
    }
    if (!mediaLibraryTrigger->Init(triggers, table)) {
        MEDIA_ERR_LOG("MediaLibraryTrigger fail to init");
        return nullptr;
    }
    MEDIA_INFO_LOG("prepare %{public}zu triggers for key: %{public}s", triggers.size(), triggerKey.c_str());
    return mediaLibraryTrigger;
}
} // namespace Media
} // namespace OHOS
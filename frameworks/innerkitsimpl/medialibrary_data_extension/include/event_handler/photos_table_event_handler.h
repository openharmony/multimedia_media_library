/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PHOTOS_TABLE_EVENT_HANDLER_H
#define OHOS_MEDIA_PHOTOS_TABLE_EVENT_HANDLER_H

#include <string>

#include "rdb_store.h"
#include "i_media_rdb_open_event.h"
#include "database_utils.h"
#include "media_column.h"

namespace OHOS::Media {
class PhotosTableEventHandler : public IMediaRdbOpenEvent {
public:
    virtual ~PhotosTableEventHandler() = default;

public:
    int32_t OnCreate(std::shared_ptr<MediaLibraryRdbStore> store) override;
    int32_t OnUpgrade(std::shared_ptr<MediaLibraryRdbStore> store, int32_t oldVersion, int32_t newVersion) override;

private:
    using UpgradeHandle = int32_t (PhotosTableEventHandler::*)(std::shared_ptr<MediaLibraryRdbStore>, int32_t, int32_t);
    int32_t AddWriterCodeColumn(std::shared_ptr<MediaLibraryRdbStore> store, int32_t oldVersion, int32_t newVersion);
    int32_t UpgradeTriggerForWriterCode(
        std::shared_ptr<MediaLibraryRdbStore> store, int32_t oldVersion, int32_t newVersion);

private:
    const std::vector<UpgradeHandle> upgradeHandles_ = {
        &PhotosTableEventHandler::AddWriterCodeColumn,
        &PhotosTableEventHandler::UpgradeTriggerForWriterCode,
    };

private:
    const std::string SQL_WRITER_CODE_COLUMN_ADD = "\
        ALTER TABLE Photos \
        ADD COLUMN writer_code INT \
            NOT NULL DEFAULT 0 ;";
    const std::string SQL_CREATE_PHOTOS_FDIRTY_TRIGGER = PhotoColumn::CREATE_PHOTOS_FDIRTY_TRIGGER;
    const std::string SQL_DROP_PHOTOS_FDIRTY_TRIGGER = "DROP TRIGGER IF EXISTS photos_fdirty_trigger;";
    const std::string SQL_CREATE_PHOTOS_MDIRTY_TRIGGER = PhotoColumn::CREATE_PHOTOS_MDIRTY_TRIGGER;
    const std::string SQL_DROP_PHOTOS_MDIRTY_TRIGGER = "DROP TRIGGER IF EXISTS photos_mdirty_trigger;";
    const std::string SQL_CREATE_PHOTOS_DELETE_TRIGGER = PhotoColumn::CREATE_PHOTOS_DELETE_TRIGGER;
    const std::string SQL_DROP_PHOTOS_DELETE_TRIGGER = "DROP TRIGGER IF EXISTS photos_delete_trigger;";

private:
    DatabaseUtils dbUpgradeUtils_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_PHOTOS_TABLE_EVENT_HANDLER_H
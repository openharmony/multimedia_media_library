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
#include "gallery_db_upgrade.h"
 
#include "rdb_store.h"
#include "album_plugin_table_event_handler.h"
#include "media_log.h"
 
namespace OHOS::Media {
namespace DataTransfer {
/**
 * @brief Upgrade the database, before data restore or clone.
 */
int32_t GalleryDbUpgrade::OnUpgrade(NativeRdb::RdbStore &store)
{
    MEDIA_INFO_LOG("GalleryDbUpgrade::OnUpgrade start.");
    AlbumPluginTableEventHandler handler;
    int32_t ret = handler.OnUpgrade(store, 0, 0);
    MEDIA_INFO_LOG("GalleryDbUpgrade::OnUpgrade end, ret: %{public}d", ret);
    return ret;
}
}  // namespace DataTransfer
}  // namespace OHOS::Media
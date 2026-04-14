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

#include "persist_permission_column.h"

namespace OHOS {
namespace Media {

const std::string PersistPermissionColumn::ID = "id";
const std::string PersistPermissionColumn::PERSIST_TOKENID = "tokenid";
const std::string PersistPermissionColumn::PERSIST_APPIDENTIFIER = "appIdentifier";
const std::string PersistPermissionColumn::PERSIST_BUNDLE_NAME = "bundle_name";
const std::string PersistPermissionColumn::PERSIST_BUNDLE_INDEX = "bundle_index";

const std::string PersistPermissionColumn::PERSIST_PERMISSION_TABLE = "Persist_Permission";

const std::string PersistPermissionColumn::CREATE_PERSIST_PERMISSION_TABLE =
    "CREATE TABLE IF NOT EXISTS " + PersistPermissionColumn::PERSIST_PERMISSION_TABLE + "(" +
    PersistPermissionColumn::ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
    PersistPermissionColumn::PERSIST_TOKENID + " BIGINT, " +
    PersistPermissionColumn::PERSIST_APPIDENTIFIER + " TEXT, " +
    PersistPermissionColumn::PERSIST_BUNDLE_NAME + " TEXT, " +
    PersistPermissionColumn::PERSIST_BUNDLE_INDEX + " INTEGER)";

} // namespace Media
} // namespace OHOS

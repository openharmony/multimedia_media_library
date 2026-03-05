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

#ifndef CLONE_RESTORE_SELECTION_SOURCE_H
#define CLONE_RESTORE_SELECTION_SOURCE_H

#include <string>

#include "backup_const_column.h"

namespace OHOS {
namespace Media {

enum class SelectionInsertType {
    PHOTOS = 0,
    SELECTION,
    ATOM_EVENT,
    ANALYSIS_TOTAL,
};

class CloneRestoreSelectionSource {
public:
    void Init(const std::string &path, const std::vector<std::string> &tableList);
    void Insert(const vector<string> &tableList, std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertByType(SelectionInsertType insertType, std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertPhoto(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertSelection(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertAtomEvent(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);
    void InsertAnalysisTotal(std::shared_ptr<NativeRdb::RdbStore> rdbPtr);

public:
    std::shared_ptr<NativeRdb::RdbStore> cloneStorePtr_;
};

class CloneRestoreSelectionOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    void Init(const std::vector<std::string> &tableList);
    std::vector<std::string> createSqls_;
};

} // namespace Media
} // namespace OHOS
#endif
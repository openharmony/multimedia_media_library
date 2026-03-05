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

#ifndef CLONE_RESTORE_SELECTION_TEST_H
#define CLONE_RESTORE_SELECTION_TEST_H

#include "gtest/gtest.h"
#include "rdb_helper.h"
#include "result_set_utils.h"
#include "backup_const.h"
#include "clone_restore_selection_source.h"

namespace OHOS {
namespace Media {

class CloneRestoreSelectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void Init(CloneRestoreSelectionSource &selectionSource, const string &path, const vector<string> &tableList);
    void VerifySelectionRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void VerifyAtomEventRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void SetupMockPhotoInfoMap(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
    void SetupMockPhotoInfoMapMultiple(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
    void SetupMockPhotoInfoMapWithMissing(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
};

} // Media
} // OHOS
#endif
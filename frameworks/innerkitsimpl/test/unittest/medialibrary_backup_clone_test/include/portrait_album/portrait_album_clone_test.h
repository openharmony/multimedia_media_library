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

#ifndef MEDIALIBRARY_BACKUP_CLONE_TEST_H
#define MEDIALIBRARY_BACKUP_CLONE_TEST_H

#include "gtest/gtest.h"
#include "rdb_helper.h"
#include "result_set_utils.h"
#include "backup_const.h"
#include "portrait_album_source.h"

namespace OHOS {
namespace Media {
class PortraitAlbumCloneTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void Init(PortraitAlbumSource &portraitAlbumSource, const string &path, const vector<string> &tableList);
    void VerifyPortraitAlbumRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void VerifyMaps(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void VerifyPortraitClusteringRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void VerifyImageFaceRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    void SetupMockPhotoInfoMap(std::unordered_map<int32_t, PhotoInfo> &photoInfoMap);
    void SetupMockPortraitAlbumInfoMap(std::vector<AnalysisAlbumTbl> &portraitAlbumInfoMap);
};
} // Media
} // OHOS
#endif
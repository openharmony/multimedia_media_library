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

#ifndef MEDIALIBRARY_BACKUP_CLONE_TEST_H
#define MEDIALIBRARY_BACKUP_CLONE_TEST_H

#include "gtest/gtest.h"
#include "rdb_helper.h"
#include "result_set_utils.h"
#include "backup_const.h"

namespace OHOS {
namespace Media {
class MediaLibraryBackupCloneTest : public testing::Test {
public:
    static constexpr int32_t FILE_INFO_NEW_ID = 101;
    static constexpr int32_t PORTRAIT_SUBTYPE = 4102;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void VerifyPortraitAlbumRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    static void VerifyPortraitClusteringRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    static void SetupMockImgFaceData(std::vector<FileInfo>& fileInfos);
    static void VerifyImageFaceRestore(const std::shared_ptr<NativeRdb::RdbStore>& db,
        const std::vector<FileInfo>& fileInfos);
    static void VerifyGeoDictionaryRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    static void VerifyClassifyRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    static void VerifyClassifyVideoRestore(const std::shared_ptr<NativeRdb::RdbStore>& db);
    static void InsertSampleSearchIndexData(const std::shared_ptr<NativeRdb::RdbStore>& db,
        int32_t fileId, const std::string& data, const std::string& displayName, double latitude, double longitude,
        int64_t dateModified, int32_t photoStatus, int32_t cvStatus, int32_t geoStatus, int32_t version,
        const std::string& systemLanguage);
    static void VerifySearchIndexRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        const std::unordered_map<int32_t, PhotoInfo>& photoInfoMap);
    static void VerifyBeautyScoreRestore(const std::shared_ptr<NativeRdb::RdbStore>& destRdb,
        const std::unordered_map<int32_t, OHOS::Media::PhotoInfo>& photoInfoMap);   
};
} // namespace Media
} // namespace OHOS
#endif // MEDIALIBRARY_BACKUP_CLONE_TEST_H

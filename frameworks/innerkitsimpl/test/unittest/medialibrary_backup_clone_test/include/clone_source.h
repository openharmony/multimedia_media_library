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

#ifndef CLONE_SOURCE_H
#define CLONE_SOURCE_H

#include <string>

#include "result_set_utils.h"
#include "rdb_helper.h"

namespace OHOS {
namespace Media {
class CloneOpenCall;

class CloneSource {
public:
    void Init(const std::string &path, const std::vector<std::string> &tableList);
    void Insert(const std::vector<std::string> &tableList);
    void InsertByType(int32_t insertType);
    void InsertPhoto();
    void InsertPhotoAlbum();
    void InsertPhotoMap();
    void InsertAnalysisAlbum();
    void InsertAnalysisPhotoMap();
    void InsertAudio();
    std::shared_ptr<NativeRdb::RdbStore> cloneStorePtr_;
};

class CloneOpenCall : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    void Init(const std::vector<std::string> &tableList);
    std::vector<std::string> createSqls_;
};
} // namespace Media
} // namespace OHOS
#endif // CLONE_SOURCE_H
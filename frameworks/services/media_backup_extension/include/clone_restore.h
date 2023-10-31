/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_CLONE_RESTORE_H
#define OHOS_MEDIA_CLONE_RESTORE_H

#include "base_restore.h"

namespace OHOS {
namespace Media {
class CloneRestore : public BaseRestore {
public:
    CloneRestore() = default;
    virtual ~CloneRestore() = default;
    // updatePath is useless now
    int32_t Init(const std::string &orignPath, const std::string &updatePath, bool isUpdate) override;

private:
    void RestorePhoto(void) override;
    void HandleRestData(void) override;
    int32_t QueryTotalNumber(void) override;
    std::vector<FileInfo> QueryFileInfos(int32_t offset) override;
    bool ParseResultSet(const std::shared_ptr<NativeRdb::ResultSet> &resultSet, FileInfo &info) override;

private:
    std::shared_ptr<NativeRdb::RdbStore> mediaRdb_;
    std::string filePath_;
    std::string dbPath_;
};
} // namespace Media
} // namespace OHOS

#endif  // OHOS_MEDIA_CLONE_RESTORE_H

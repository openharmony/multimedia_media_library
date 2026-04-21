/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_PORTRAIT_NICKNAME_REPOSITORY_H
#define OHOS_MEDIA_PORTRAIT_NICKNAME_REPOSITORY_H

#include <memory>
#include <string>
#include <vector>

#include "medialibrary_rdbstore.h"

namespace OHOS::Media {
class PortraitNickNameRepository {
public:
    explicit PortraitNickNameRepository(const std::shared_ptr<MediaLibraryRdbStore> &rdbStore);

    bool Exists(const std::string &albumId) const;
    int32_t QueryNickNameCount(const std::string &albumId, int32_t &count) const;
    int32_t QueryExistingNickNameCount(const std::string &albumId, const std::vector<std::string> &nickNames,
        int32_t &count) const;
    int32_t CheckNickNameLimit(const std::string &albumId, const std::vector<std::string> &nickNames) const;
    int32_t InsertNickNames(const std::string &albumId, const std::vector<std::string> &nickNames) const;
    int32_t QueryNickNames(const std::vector<std::string> &albumIds, std::vector<std::string> &nickNames) const;
    int32_t DeleteNickNames(const std::vector<std::string> &albumIds) const;
    int32_t DeleteNickNames(const std::vector<std::string> &albumIds,
        const std::vector<std::string> &nickNames) const;

private:
    std::shared_ptr<MediaLibraryRdbStore> rdbStore_;
};
} // namespace OHOS::Media

#endif // OHOS_MEDIA_PORTRAIT_NICKNAME_REPOSITORY_H

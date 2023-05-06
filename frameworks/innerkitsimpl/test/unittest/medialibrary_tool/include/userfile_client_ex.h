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
#ifndef FRAMEWORKS_MEDIATOOLS_USER_FILE_CLIENT_EX_H_
#define FRAMEWORKS_MEDIATOOLS_USER_FILE_CLIENT_EX_H_
#include <string>

#include "fetch_result.h"
#include "iremote_object.h"

namespace OHOS {
namespace Media {
namespace MediaTool {
class UserFileClientEx {
public:
    static bool Init(const sptr<IRemoteObject> &token);
    static int32_t Insert(const MediaType mediaType, const std::string &name);
    static int32_t Query(const MediaType mediaType, const std::string &uri,
        std::shared_ptr<FetchResult<FileAsset>> &fetchResult);
    static int Open(const std::string &uri, const std::string &mode);
    static int Close(const std::string &uri, const int fileFd, const std::string &mode);
    static int32_t CreateThumbnail(const std::string &uri);
    static std::string GetTableNameByMediaType(const MediaType mediaType);
    static std::string GetTableNameByUri(const std::string &uri);
};
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_MEDIATOOLS_USER_FILE_CLIENT_EX_H_

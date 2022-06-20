/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#ifndef FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_
#define FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

#include <string>

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "result_set.h"
#include "timer.h"
#include "uri.h"
#include "values_bucket.h"
#include "want.h"
#include "file_extension_info.h"
#include "media_lib_service_const.h"

namespace OHOS {
namespace Media {
class MediaFileExtentionUtils {
public:
    static std::string GetFileMediaTypeUri(MediaType mediaType, const std::string& networkId);
    static int32_t Mkdir(Uri parentUri, std::string displayName, Uri& newDirUri,
        const std::shared_ptr<NativeRdb::RdbStore> &rdbStore);
    static int32_t Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri);
    static std::vector<FileAccessFwk::FileInfo> ListFile(std::string selectUri);
    static std::vector<FileAccessFwk::DeviceInfo> GetRoots();
};
} // Media
} // OHOS

#endif // FRAMEWORKS_SERVICES_MEDIA_LIBRARY_EXTENTION_UTILS_H_

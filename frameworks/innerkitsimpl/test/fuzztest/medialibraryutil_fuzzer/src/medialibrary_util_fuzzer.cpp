/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibrary_util_fuzzer.h"

#include <cstdint>
#include <string>

#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_uripermission_operations.h"

namespace OHOS {
using namespace std;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data)
{
    return static_cast<int32_t>(*data);
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    return Uri(FuzzString(data, size));
}

static void CommandTest(const uint8_t *data, size_t size)
{
    NativeRdb::ValuesBucket value;
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    cmd.SetTableName(FuzzString(data, size));
    cmd.SetBundleName(FuzzString(data, size));
    cmd.SetDeviceName(FuzzString(data, size));
    cmd.SetResult(FuzzString(data, size));
    cmd.SetOprnAssetId(FuzzString(data, size));
    cmd.SetOprnObject(static_cast<Media::OperationObject>(FuzzInt32(data)));
    cmd.GetOprnFileId();
    DataShare::DataSharePredicates pred;
    cmd.SetDataSharePred(pred);
    cmd.SetValueBucket(value);
    Media::MediaLibraryCommand cmdValueBucket(FuzzUri(data, size), value);
    Media::MediaLibraryCommand cmdValueBucket2(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), value,
        static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MediaLibraryCommand cmdDevice(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), FuzzString(data, size),
        static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
}

static void DirOperationTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::MediaLibraryDirOperations::HandleDirOperation(cmd);
    Media::MediaLibraryDirOperations::CreateDirOperation(cmd);
    Media::MediaLibraryDirOperations::TrashDirOperation(cmd);
}

static void UriPermissionTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(FuzzInt32(data)),
        static_cast<Media::OperationType>(FuzzInt32(data)), static_cast<Media::MediaLibraryApi>(FuzzInt32(data)));
    Media::UriPermissionOperations::HandleUriPermOperations(cmd);
    Media::UriPermissionOperations::HandleUriPermInsert(cmd);
    Media::UriPermissionOperations::InsertBundlePermission(FuzzInt32(data), FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    Media::UriPermissionOperations::DeleteBundlePermission(FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    string mode = "r";
    Media::UriPermissionOperations::CheckUriPermission(FuzzString(data, size), mode);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::CommandTest(data, size);
    OHOS::DirOperationTest(data, size);
    OHOS::UriPermissionTest(data, size);
    return 0;
}

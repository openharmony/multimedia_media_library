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

#include "medialibrary_asset_operations.h"

#include <algorithm>
#include <dirent.h>
#include <mutex>

#include "media_column.h"
#include "media_errors.h"
#include "media_log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_tracer.h"
#include "medialibrary_unistore_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
int32_t MediaLibraryAssetOperations::HandleInsertOperation(MediaLibraryCommand &cmd)
{
    int errCode = E_ERR;
    switch (cmd.GetOprnType()) {
        case OperationType::CREATE:
            errCode = CreateOperation(cmd);
            break;
        case OperationType::CLOSE:
            errCode = CloseOperation(cmd);
            break;
        default:
            MEDIA_ERR_LOG("unknown operation type %{public}d", cmd.GetOprnType());
            break;
    }
    return errCode;
}

int32_t MediaLibraryAssetOperations::CreateOperation(MediaLibraryCommand &cmd)
{
    // CreateAsset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Create(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Create(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FileSysetm_Asset is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::DeleteOperation(MediaLibraryCommand &cmd)
{
    // delete Asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Delete(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("delete asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

shared_ptr<NativeRdb::ResultSet> MediaLibraryAssetOperations::QueryOperation(
    MediaLibraryCommand &cmd, const vector<string> &columns)
{
    // query asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Query(cmd, columns);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return nullptr;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("api9 operation is not finished");
            return nullptr;
        default:
            MEDIA_ERR_LOG("error operation object");
            return nullptr;
    }
}

int32_t MediaLibraryAssetOperations::UpdateOperation(MediaLibraryCommand &cmd)
{
    // Update asset specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Update(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Update(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("create asset by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::OpenOperation(MediaLibraryCommand &cmd, const string &mode)
{
    // Open specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Open(cmd, mode);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Open(cmd, mode);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("open by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}

int32_t MediaLibraryAssetOperations::CloseOperation(MediaLibraryCommand &cmd)
{
    // Close specify type
    switch (cmd.GetOprnObject()) {
        case OperationObject::FILESYSTEM_PHOTO:
            return MediaLibraryPhotoOperations::Close(cmd);
        case OperationObject::FILESYSTEM_AUDIO:
            return MediaLibraryAudioOperations::Close(cmd);
        case OperationObject::FILESYSTEM_DOCUMENT:
            MEDIA_ERR_LOG("document operation is not finished");
            return E_INVALID_VALUES;
        case OperationObject::FILESYSTEM_ASSET:
            MEDIA_ERR_LOG("close by FILESYSTEM_ASSET is deperated");
            return E_INVALID_VALUES;
        default:
            MEDIA_ERR_LOG("error operation object");
            return E_INVALID_VALUES;
    }
}
} // namespace Media
} // namespace OHOS
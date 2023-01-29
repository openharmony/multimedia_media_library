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
#define MLOG_TAG "FileExtension"

#include "media_file_ext_ability.h"

#include "extension_context.h"
#include "file_access_ext_stub_impl.h"
#include "js_runtime_utils.h"
#include "media_file_extention_utils.h"
#include "media_log.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::FileAccessFwk;
using namespace OHOS::DataShare;

MediaFileExtAbility::MediaFileExtAbility(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

MediaFileExtAbility::~MediaFileExtAbility() {}

MediaFileExtAbility* MediaFileExtAbility::Create(const unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("create MediaFileExtAbility");
    return new MediaFileExtAbility(static_cast<JsRuntime&>(*runtime));
}

static MediaFileExtAbility* MediaFileExtCreator(const unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    return  MediaFileExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterFileExtCreator()
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    FileAccessExtAbility::SetCreator(MediaFileExtCreator);
}

void MediaFileExtAbility::Init(const shared_ptr<AbilityLocalRecord> &record,
    const shared_ptr<OHOSApplication> &application, shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    MEDIA_INFO_LOG("Init MediaFileExtAbility");
    FileAccessExtAbility::Init(record, application, handler, token);
    auto context = AbilityRuntime::Context::GetApplicationContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context, nullptr);
}

void MediaFileExtAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("Onstart MediaFileExtAbility");
    Extension::OnStart(want);
}

void MediaFileExtAbility::OnStop()
{
    MEDIA_INFO_LOG("%{public}s begin.", __func__);
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

sptr<IRemoteObject> MediaFileExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_DEBUG_LOG("OnConnect MediaFileExtAbility");
    Extension::OnConnect(want);
    sptr<FileAccessExtStubImpl> remoteObject = new (nothrow) FileAccessExtStubImpl(
        static_pointer_cast<MediaFileExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine()));
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("OnConnect MediaFileExtAbility get obj fail");
        return nullptr;
    }

    return remoteObject->AsObject();
}

int32_t ConvertErrno(int32_t innerErr)
{
    if (innerErr >= 0) {
        return E_SUCCESS;
    }
    int32_t err = JS_INNER_FAIL;
    if (ClientErrTable.find(innerErr) != ClientErrTable.end()) {
        err = ClientErrTable.at(innerErr);
    }
    return err;
}

int MediaFileExtAbility::OpenFile(const Uri &uri, const int flags, int &fd)
{
    return ConvertErrno(MediaFileExtentionUtils::OpenFile(uri, flags, fd));
}

int MediaFileExtAbility::CreateFile(const Uri &parentUri, const string &displayName,  Uri &newFileUri)
{
    return ConvertErrno(MediaFileExtentionUtils::CreateFile(parentUri, displayName, newFileUri));
}

int MediaFileExtAbility::Mkdir(const Uri &parentUri, const string &displayName, Uri &newFileUri)
{
    return ConvertErrno(MediaFileExtentionUtils::Mkdir(parentUri, displayName, newFileUri));
}

int MediaFileExtAbility::Delete(const Uri &sourceFileUri)
{
    return ConvertErrno(MediaFileExtentionUtils::Delete(sourceFileUri));
}

int MediaFileExtAbility::ListFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, vector<FileInfo> &fileList)
{
    return ConvertErrno(MediaFileExtentionUtils::ListFile(parentInfo, offset, maxCount, filter, fileList));
}

int MediaFileExtAbility::ScanFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, vector<FileInfo> &fileList)
{
    return ConvertErrno(MediaFileExtentionUtils::ScanFile(parentInfo, offset, maxCount, filter, fileList));
}

int MediaFileExtAbility::GetRoots(vector<FileAccessFwk::RootInfo> &rootList)
{
    return ConvertErrno(MediaFileExtentionUtils::GetRoots(rootList));
}

int MediaFileExtAbility::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    return ConvertErrno(MediaFileExtentionUtils::Move(sourceFileUri, targetParentUri, newFileUri));
}

int MediaFileExtAbility::Rename(const Uri &sourceFileUri, const string &displayName, Uri &newFileUri)
{
    return ConvertErrno(MediaFileExtentionUtils::Rename(sourceFileUri, displayName, newFileUri));
}

int MediaFileExtAbility::Access(const Uri &uri, bool &isExist)
{
    return ConvertErrno(MediaFileExtentionUtils::Access(uri, isExist));
}
} // Media
} // OHOS

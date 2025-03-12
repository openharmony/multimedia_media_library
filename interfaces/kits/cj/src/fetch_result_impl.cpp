/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fetch_result_impl.h"

using namespace std;
using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
FetchResultImpl::FetchResultImpl(unique_ptr<FfiFetchResultProperty> propertyPtr_)
{
    propertyPtr = move(propertyPtr_);
}

std::shared_ptr<FetchResult<FileAsset>> FetchResultImpl::GetFetchFileResultObject()
{
    return propertyPtr->fetchFileResult_;
}

std::shared_ptr<FetchResult<AlbumAsset>> FetchResultImpl::GetFetchAlbumResultObject()
{
    return propertyPtr->fetchAlbumResult_;
}

std::shared_ptr<FetchResult<PhotoAlbum>> FetchResultImpl::GetFetchPhotoAlbumResultObject()
{
    return propertyPtr->fetchPhotoAlbumResult_;
}

std::shared_ptr<FetchResult<SmartAlbumAsset>> FetchResultImpl::GetFetchSmartAlbumResultObject()
{
    return propertyPtr->fetchSmartAlbumResult_;
}

int32_t FetchResultImpl::GetCount(int32_t &errCode)
{
    int32_t count = 0;
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE:
            count = propertyPtr->fetchFileResult_->GetCount();
            break;
        case FetchResType::TYPE_ALBUM:
            count = propertyPtr->fetchAlbumResult_->GetCount();
            break;
        case FetchResType::TYPE_PHOTOALBUM:
            count = propertyPtr->fetchPhotoAlbumResult_->GetCount();
            break;
        case FetchResType::TYPE_SMARTALBUM:
            count = propertyPtr->fetchSmartAlbumResult_->GetCount();
            break;
        default:
            LOGE("unsupported FetchResType");
            break;
    }
    if (count < 0) {
        errCode = JS_INNER_FAIL;
    }
    return count;
}

bool FetchResultImpl::IsAfterLast(int32_t &errCode)
{
    bool isAfterLast = false;
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE:
            isAfterLast = propertyPtr->fetchFileResult_->IsAtLastRow();
            break;
        case FetchResType::TYPE_ALBUM:
            isAfterLast = propertyPtr->fetchAlbumResult_->IsAtLastRow();
            break;
        case FetchResType::TYPE_PHOTOALBUM:
            isAfterLast = propertyPtr->fetchPhotoAlbumResult_->IsAtLastRow();
            break;
        case FetchResType::TYPE_SMARTALBUM:
            isAfterLast = propertyPtr->fetchSmartAlbumResult_->IsAtLastRow();
            break;
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return isAfterLast;
}

void FetchResultImpl::Close()
{
    propertyPtr = nullptr;
}

static void GetFileAssetObj(unique_ptr<FileAsset> fileAsset,
    FetchResultObject &fetchResultObject, int32_t &errCode)
{
    fetchResultObject.id = -1;
    fetchResultObject.fetchResType = static_cast<int32_t>(FetchResType::TYPE_FILE);
    if (fileAsset != nullptr) {
        auto native = FFIData::Create<PhotoAssetImpl>(move(fileAsset));
        if (native != nullptr) {
            fetchResultObject.id = native->GetID();
            return;
        }
    }
    errCode = JS_INNER_FAIL;
}

static void GetPhotoAlbumObj(unique_ptr<PhotoAlbum> photoAlbum,
    FetchResultObject &fetchResultObject, int32_t &errCode)
{
    fetchResultObject.id = -1;
    fetchResultObject.fetchResType = static_cast<int32_t>(FetchResType::TYPE_PHOTOALBUM);
    if (photoAlbum != nullptr) {
        auto native = FFIData::Create<PhotoAlbumImpl>(move(photoAlbum));
        if (native != nullptr) {
            fetchResultObject.id = native->GetID();
        } else {
            errCode = JS_INNER_FAIL;
        }
    } else {
        errCode = JS_INNER_FAIL;
    }
}

FetchResultObject FetchResultImpl::GetFirstObject(int32_t &errCode)
{
    FetchResultObject fetchResultObject = {
        .id = -1,
        .fetchResType = 0
    };
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = propertyPtr->fetchFileResult_->GetFirstObject();
            GetFileAssetObj(move(fileAsset), fetchResultObject, errCode);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetFirstObject();
            GetPhotoAlbumObj(move(photoAlbum), fetchResultObject, errCode);
            break;
        }
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return fetchResultObject;
}

FetchResultObject FetchResultImpl::GetNextObject(int32_t &errCode)
{
    FetchResultObject fetchResultObject = {
        .id = -1,
        .fetchResType = 0
    };
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = propertyPtr->fetchFileResult_->GetNextObject();
            GetFileAssetObj(move(fileAsset), fetchResultObject, errCode);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetNextObject();
            GetPhotoAlbumObj(move(photoAlbum), fetchResultObject, errCode);
            break;
        }
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return fetchResultObject;
}

FetchResultObject FetchResultImpl::GetLastObject(int32_t &errCode)
{
    FetchResultObject fetchResultObject = {
        .id = -1,
        .fetchResType = 0
    };
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = propertyPtr->fetchFileResult_->GetLastObject();
            GetFileAssetObj(move(fileAsset), fetchResultObject, errCode);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetLastObject();
            GetPhotoAlbumObj(move(photoAlbum), fetchResultObject, errCode);
            break;
        }
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return fetchResultObject;
}

FetchResultObject FetchResultImpl::GetObjectAtPosition(int32_t position, int32_t &errCode)
{
    FetchResultObject fetchResultObject = {
        .id = -1,
        .fetchResType = 0
    };
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            fileAsset = propertyPtr->fetchFileResult_->GetObjectAtPosition(position);
            GetFileAssetObj(move(fileAsset), fetchResultObject, errCode);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            photoAlbum = propertyPtr->fetchPhotoAlbumResult_->GetObjectAtPosition(position);
            GetPhotoAlbumObj(move(photoAlbum), fetchResultObject, errCode);
            break;
        }
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return fetchResultObject;
}

static void GetArryFileAssetObj(vector<unique_ptr<FileAsset>> &fileAssetArray,
    const shared_ptr<FetchResult<FileAsset>> &fetchResult,
    CArrayFetchResultObject &cArrayFetchResultObject, int32_t &errCode)
{
    errCode = E_SUCCESS;
    auto file = fetchResult->GetFirstObject();
    while (file != nullptr) {
        fileAssetArray.push_back(move(file));
        file = fetchResult->GetNextObject();
    }
    size_t fileAssetArraySize = fileAssetArray.size();
    if (fileAssetArraySize <= 0) {
        LOGE("fileAssetArray size error");
        errCode = JS_INNER_FAIL;
        return;
    }
    FetchResultObject* head =
        static_cast<FetchResultObject *>(malloc(sizeof(FetchResultObject) * fileAssetArraySize));
    if (head == nullptr) {
        LOGE("malloc fileAssetArray failed.");
        errCode = JS_INNER_FAIL;
        return;
    }
    int32_t count = 0;
    for (size_t i = 0; i < fileAssetArraySize; i++) {
        if (errCode != E_SUCCESS) {
            LOGE("GetFileAssetObj failed.");
            for (int32_t j = 0; j < count; j++) {
                FfiOHOSFFIFFIDataRelease(head[j].id);
            }
            free(head);
            return;
        }
        GetFileAssetObj(move(fileAssetArray[i]), head[count], errCode);
        count++;
    }
    cArrayFetchResultObject.head = head;
    cArrayFetchResultObject.size = static_cast<int64_t>(count);
}

static void GetArryPhotoAlbumObj(vector<unique_ptr<PhotoAlbum>> &filePhotoAlbumArray,
    const shared_ptr<FetchResult<PhotoAlbum>> &fetchResult,
    CArrayFetchResultObject &cArrayFetchResultObject, int32_t &errCode)
{
    errCode = E_SUCCESS;
    auto file = fetchResult->GetFirstObject();
    while (file != nullptr) {
        filePhotoAlbumArray.push_back(move(file));
        file = fetchResult->GetNextObject();
    }
    size_t filePhotoAlbumArraySize = filePhotoAlbumArray.size();
    if (filePhotoAlbumArraySize < 0) {
        LOGE("filePhotoAlbumArray size error");
        errCode = JS_INNER_FAIL;
        return;
    }
    FetchResultObject* head =
        static_cast<FetchResultObject *>(malloc(sizeof(FetchResultObject) * filePhotoAlbumArraySize));
    if (head == nullptr) {
        LOGE("malloc filePhotoAlbumArray failed.");
        errCode = JS_INNER_FAIL;
        return;
    }
    int32_t count = 0;
    for (size_t i = 0; i < filePhotoAlbumArraySize; i++) {
        if (errCode != E_SUCCESS) {
            LOGE("GetPhotoAlbumObj failed.");
            for (int32_t j = 0; j < count; j++) {
                FfiOHOSFFIFFIDataRelease(head[j].id);
            }
            free(head);
            return;
        }
        GetPhotoAlbumObj(move(filePhotoAlbumArray[i]), head[count], errCode);
        count++;
    }
    cArrayFetchResultObject.head = head;
    cArrayFetchResultObject.size = static_cast<int64_t>(count);
}

CArrayFetchResultObject FetchResultImpl::GetAllObjects(int32_t &errCode)
{
    CArrayFetchResultObject cArrayFetchResultObject = {
        .head = nullptr,
        .size = 0
    };
    switch (propertyPtr->fetchResType_) {
        case FetchResType::TYPE_FILE: {
            auto fetchResult = propertyPtr->fetchFileResult_;
            fileAssetArray.clear();
            GetArryFileAssetObj(fileAssetArray, fetchResult, cArrayFetchResultObject, errCode);
            break;
        }
        case FetchResType::TYPE_PHOTOALBUM: {
            auto fetchResult = propertyPtr->fetchPhotoAlbumResult_;
            filePhotoAlbumArray.clear();
            GetArryPhotoAlbumObj(filePhotoAlbumArray, fetchResult, cArrayFetchResultObject, errCode);
            break;
        }
        default:
            LOGE("unsupported FetchResType");
            errCode = JS_INNER_FAIL;
            break;
    }
    return cArrayFetchResultObject;
}
}
}
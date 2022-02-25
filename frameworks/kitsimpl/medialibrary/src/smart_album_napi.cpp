/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "smart_album_napi.h"
#include "hilog/log.h"

using OHOS::HiviewDFX::HiLog;
using OHOS::HiviewDFX::HiLogLabel;

namespace {
    constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "SmartAlbumNapi"};
}

namespace OHOS {
namespace Media {
using namespace std;
napi_ref SmartAlbumNapi::sConstructor_ = nullptr;
SmartAlbumAsset *SmartAlbumNapi::sAlbumData_ = nullptr;
std::shared_ptr<AppExecFwk::DataAbilityHelper> SmartAlbumNapi::sAbilityHelper = nullptr;
using CompleteCallback = napi_async_complete_callback;

SmartAlbumNapi::SmartAlbumNapi()
    : env_(nullptr), wrapper_(nullptr)
{
    albumId_ = DEFAULT_ALBUM_ID;
    albumName_ = DEFAULT_ALBUM_NAME;
    albumUri_ = DEFAULT_ALBUM_URI;
    albumTag_ = DEFAULT_SMART_ALBUM_TAG;
    albumPrivateType_ = DEFAULT_SMART_ALBUM_PRIVATE_TYPE;
    albumCapacity_ = DEFAULT_SMART_ALBUM_ALBUMCAPACITY;
    albumCategoryId_ = DEFAULT_SMART_ALBUM_CATEGORYID;
    albumCategoryName_ = DEFAULT_SMART_ALBUM_CATEGORYNAME;
    albumCoverUri_ = DEFAULT_COVERURI;
}
SmartAlbumNapi::~SmartAlbumNapi()
{
    if (wrapper_ != nullptr) {
        napi_delete_reference(env_, wrapper_);
    }
}

void SmartAlbumNapi::SmartAlbumNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    SmartAlbumNapi *album = reinterpret_cast<SmartAlbumNapi*>(nativeObject);
    if (album != nullptr) {
        album->~SmartAlbumNapi();
    }
}

napi_value SmartAlbumNapi::Init(napi_env env, napi_value exports)
{
    HiLog::Error(LABEL, "SmartAlbumNapi::Init");
    napi_status status;
    napi_value ctorObj;
    int32_t refCount = 1;

    napi_property_descriptor album_props[] = {
        DECLARE_NAPI_GETTER("albumId", JSGetSmartAlbumId),
        DECLARE_NAPI_GETTER("albumUri", JSGetSmartAlbumUri),
        DECLARE_NAPI_GETTER_SETTER("albumName", JSGetSmartAlbumName, JSSmartAlbumNameSetter),
        DECLARE_NAPI_GETTER("albumTag", JSGetSmartAlbumTag),
        DECLARE_NAPI_GETTER("albumCapacity", JSGetSmartAlbumCapacity),
        DECLARE_NAPI_GETTER("categoryId", JSGetSmartAlbumCategoryId),
        DECLARE_NAPI_GETTER("categoryName", JSGetSmartAlbumCategoryName),
        DECLARE_NAPI_GETTER("coverUri", JSGetSmartAlbumCoverUri),
        DECLARE_NAPI_FUNCTION("commitModify", JSCommitModify),
        DECLARE_NAPI_FUNCTION("addAsset", JSAddAsset),
        DECLARE_NAPI_FUNCTION("removeAsset", JSRemoveAsset),
        DECLARE_NAPI_FUNCTION("getFileAssets", JSGetSmartAlbumFileAssets)
    };

    status = napi_define_class(env, SMART_ALBUM_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH,
                               SmartAlbumNapiConstructor, nullptr,
                               sizeof(album_props) / sizeof(album_props[PARAM0]),
                               album_props, &ctorObj);
    if (status == napi_ok) {
        HiLog::Error(LABEL, "SmartAlbumNapi::Init status == napi_ok 1");
        status = napi_create_reference(env, ctorObj, refCount, &sConstructor_);
        if (status == napi_ok) {
            HiLog::Error(LABEL, "SmartAlbumNapi::Init status == napi_ok 2");
            status = napi_set_named_property(env, exports, SMART_ALBUM_NAPI_CLASS_NAME.c_str(), ctorObj);
            if (status == napi_ok) {
                HiLog::Error(LABEL, "SmartAlbumNapi::Init status == napi_ok 3");
                return exports;
            }
        }
    }
    HiLog::Error(LABEL, "SmartAlbumNapi::Init nullptr");
    return nullptr;
}

void SmartAlbumNapi::SetSmartAlbumNapiProperties(const SmartAlbumAsset &albumData)
{
    HiLog::Error(LABEL, "SetSmartAlbumNapiProperties name = %{public}s", albumData.GetAlbumName().c_str());
    this->albumId_ = albumData.GetAlbumId();
    this->albumName_ = albumData.GetAlbumName();
    this->albumUri_ = albumData.GetAlbumUri();
    this->albumTag_ = albumData.GetAlbumTag();
    this->albumPrivateType_ = albumData.GetAlbumPrivateType();
    this->albumCapacity_ = albumData.GetAlbumCapacity();
    this->albumCategoryId_ = albumData.GetCategoryId();
    this->albumCategoryName_ = albumData.GetCategoryName();
    this->albumCoverUri_ = albumData.GetCoverUri();
}

// Constructor callback
napi_value SmartAlbumNapi::SmartAlbumNapiConstructor(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value thisVar = nullptr;
    HiLog::Error(LABEL, "SmartAlbumNapiConstructor");
    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status == napi_ok && thisVar != nullptr) {
        std::unique_ptr<SmartAlbumNapi> obj = std::make_unique<SmartAlbumNapi>();
        HiLog::Error(LABEL, "SmartAlbumNapiConstructor SmartAlbumNapi");
        if (obj != nullptr) {
            obj->env_ = env;
            obj->abilityHelper_ = sAbilityHelper;
            if (sAlbumData_ != nullptr) {
                obj->SetSmartAlbumNapiProperties(*sAlbumData_);
            }
            status = napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()),
                               SmartAlbumNapi::SmartAlbumNapiDestructor, nullptr, &(obj->wrapper_));
            if (status == napi_ok) {
                obj.release();
                return thisVar;
            } else {
                HiLog::Error(LABEL, "Failure wrapping js to native napi");
            }
        }
    }

    return result;
}

napi_value SmartAlbumNapi::CreateSmartAlbumNapi(napi_env env, SmartAlbumAsset &albumData,
    std::shared_ptr<AppExecFwk::DataAbilityHelper> abilityHelper)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;
    HiLog::Error(LABEL, "CreateSmartAlbumNapi");
    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        HiLog::Error(LABEL, "CreateSmartAlbumNapi status == napi_ok");
        sAlbumData_ = &albumData;
        sAbilityHelper = abilityHelper;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        sAlbumData_ = nullptr;
        if (status == napi_ok && result != nullptr) {
            HiLog::Error(LABEL, "CreateSmartAlbumNapi status == napi_ok && result != nullptr");
            return result;
        } else {
            HiLog::Error(LABEL, "Failed to create snart album asset instance");
        }
    }

    napi_get_undefined(env, &result);
    return result;
}

std::shared_ptr<AppExecFwk::DataAbilityHelper> SmartAlbumNapi::GetDataAbilityHelper() const
{
    return abilityHelper_;
}

std::string SmartAlbumNapi::GetSmartAlbumName() const
{
    return albumName_;
}

int32_t SmartAlbumNapi::GetAlbumPrivateType() const
{
    return albumPrivateType_;
}

int32_t SmartAlbumNapi::GetSmartAlbumId() const
{
    return albumId_;
}
void SmartAlbumNapi::SetAlbumCapacity(int32_t albumCapacity)
{
    albumCapacity_ = albumCapacity;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t id;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        id = obj->albumId_;
        status = napi_create_int32(env, id, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string name = "";
    napi_value thisVar = nullptr;
    HiLog::Error(LABEL, "JSGetSmartAlbumName");
    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }
    HiLog::Error(LABEL, "JSGetSmartAlbumName status == napi_ok && thisVar != nullptr");
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        name = obj->albumName_;
        HiLog::Error(LABEL, "JSGetSmartAlbumName name = %{public}s", name.c_str());
        status = napi_create_string_utf8(env, name.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}

napi_value SmartAlbumNapi::JSSmartAlbumNameSetter(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    size_t res = 0;
    char buffer[FILENAME_MAX];
    SmartAlbumNapi* obj = nullptr;
    napi_value thisVar = nullptr;
    napi_valuetype valueType = napi_undefined;

    napi_get_undefined(env, &jsResult);
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, argc == ARGS_ONE, "requires 1 parameter");

    if (thisVar == nullptr || napi_typeof(env, argv[PARAM0], &valueType) != napi_ok
        || valueType != napi_string) {
        HiLog::Error(LABEL, "Invalid arguments type!");
        return jsResult;
    }

    napi_get_value_string_utf8(env, argv[PARAM0], buffer, FILENAME_MAX, &res);

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        obj->albumName_ = std::string(buffer);
    }

    return jsResult;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumTag(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string albumTag = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumTag = obj->albumTag_;
        status = napi_create_string_utf8(env, albumTag.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
napi_value SmartAlbumNapi::JSGetSmartAlbumCapacity(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t albumCapacity;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumCapacity = obj->albumCapacity_;
        status = napi_create_int32(env, albumCapacity, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
napi_value SmartAlbumNapi::JSGetSmartAlbumCategoryId(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    int32_t categoryId;
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        categoryId = obj->albumCategoryId_;
        status = napi_create_int32(env, categoryId, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
napi_value SmartAlbumNapi::JSGetSmartAlbumCategoryName(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string categoryName = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        categoryName = obj->albumCategoryName_;
        status = napi_create_string_utf8(env, categoryName.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
napi_value SmartAlbumNapi::JSGetSmartAlbumCoverUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string coverUri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        coverUri = obj->albumCoverUri_;
        status = napi_create_string_utf8(env, coverUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return undefinedResult;
}
napi_value SmartAlbumNapi::JSGetSmartAlbumUri(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsResult = nullptr;
    napi_value undefinedResult = nullptr;
    SmartAlbumNapi* obj = nullptr;
    std::string albumUri = "";
    napi_value thisVar = nullptr;

    napi_get_undefined(env, &undefinedResult);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        HiLog::Error(LABEL, "Invalid arguments!");
        return undefinedResult;
    }
    status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&obj));
    if (status == napi_ok && obj != nullptr) {
        albumUri = obj->albumUri_;
        status = napi_create_string_utf8(env, albumUri.c_str(), NAPI_AUTO_LENGTH, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }
    return undefinedResult;
}
static void CommitModifyNative(const SmartAlbumNapiAsyncContext &albumContext)
{
    HiLog::Error(LABEL, "CommitModifyNative");
    SmartAlbumNapiAsyncContext *context = const_cast<SmartAlbumNapiAsyncContext *>(&albumContext);
    NativeRdb::DataAbilityPredicates predicates;
    NativeRdb::ValuesBucket valuesBucket;
    int32_t changedRows;
    HiLog::Error(LABEL, "CommitModifyNative = %{public}s", context->objectInfo->GetSmartAlbumName().c_str());
    if (MediaFileUtils::CheckDisplayName(context->objectInfo->GetSmartAlbumName())) {
        valuesBucket.PutString(SMARTALBUM_DB_NAME, context->objectInfo->GetSmartAlbumName());
        predicates.EqualTo(SMARTALBUM_DB_ID, std::to_string(context->objectInfo->GetSmartAlbumId()));
        Uri CommitModifyuri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_SMARTALBUMOPRN +
                            "/" + MEDIA_SMARTALBUMOPRN_MODIFYALBUM);
        changedRows = context->objectInfo->GetDataAbilityHelper()->Update(CommitModifyuri, valuesBucket, predicates);
    } else {
        changedRows = DATA_ABILITY_VIOLATION_PARAMETERS;
    }
    context->changedRows = changedRows;
}
static void SetFileFav(bool isFavourite, SmartAlbumNapiAsyncContext *context)
{
    HiLog::Debug(LABEL, "SetFileFav IN");
    string abilityUri = MEDIALIBRARY_DATA_URI;
    NativeRdb::ValuesBucket values;
    int32_t changedRows;
    values.PutBool(MEDIA_DATA_DB_IS_FAV, isFavourite);
    Uri uri(abilityUri);
    NativeRdb::ValueObject valueObject;
    int32_t fileId = 0;
    context->valuesBucket.GetObject(SMARTALBUMMAP_DB_ASSET_ID, valueObject);
    valueObject.GetInt(fileId);

    NativeRdb::DataAbilityPredicates predicates;

    predicates.EqualTo(MEDIA_DATA_DB_ID, std::to_string(fileId));
    changedRows = context->objectInfo->GetDataAbilityHelper()->Update(uri, values, predicates);
    context->changedRows = changedRows;
    HiLog::Debug(LABEL, "SetFileFav OUT  = %{public}d", changedRows);
}

static void SetFileTrash(bool isTrash, SmartAlbumNapiAsyncContext *context)
{
    HiLog::Debug(LABEL, "SetFileTrash IN");
    string abilityUri = MEDIALIBRARY_DATA_URI;
    NativeRdb::ValuesBucket values;
    int32_t changedRows;
    if (isTrash) {
        int64_t timeNow = MediaFileUtils::UTCTimeSeconds();
        values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, timeNow);
    } else {
        values.PutLong(MEDIA_DATA_DB_DATE_TRASHED, 0);
    }

    Uri uri(abilityUri);
    NativeRdb::ValueObject valueObject;
    int32_t fileId = 0;
    context->valuesBucket.GetObject(SMARTALBUMMAP_DB_ASSET_ID, valueObject);
    valueObject.GetInt(fileId);

    NativeRdb::DataAbilityPredicates predicates;

    predicates.EqualTo(MEDIA_DATA_DB_ID, std::to_string(fileId));
    changedRows = context->objectInfo->GetDataAbilityHelper()->Update(uri, values, predicates);
    context->changedRows = changedRows;
    HiLog::Debug(LABEL, "SetFileTrash OUT  = %{public}d", changedRows);
}

static void AddAssetNative(SmartAlbumNapiAsyncContext *context)
{
    context->valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, context->objectInfo->GetSmartAlbumId());
    int32_t changedRows;
    Uri AddAsseturi(MEDIALIBRARY_DATA_URI + "/"
    + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
    changedRows =
        context->objectInfo->GetDataAbilityHelper()->Insert(AddAsseturi, context->valuesBucket);
    context->changedRows = changedRows;
}
static void RemoveAssetNative(SmartAlbumNapiAsyncContext *context)
{
    context->valuesBucket.PutInt(SMARTALBUMMAP_DB_ALBUM_ID, context->objectInfo->GetSmartAlbumId());

    int32_t changedRows;
    Uri RemoveAsseturi(MEDIALIBRARY_DATA_URI + "/"
    + MEDIA_SMARTALBUMMAPOPRN + "/" + MEDIA_SMARTALBUMMAPOPRN_REMOVESMARTALBUM);
    changedRows =
        context->objectInfo->GetDataAbilityHelper()->Insert(RemoveAsseturi, context->valuesBucket);
    context->changedRows = changedRows;
}
static void JSCommitModifyCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    HiLog::Error(LABEL, "JSCommitModifyCompleteCallback");
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->changedRows != -1) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
static void UpdateAlbumCapacity(SmartAlbumNapiAsyncContext *context)
{
    HiLog::Error(LABEL, "UpdateAlbumCapacity");
    vector<string> columns;
    NativeRdb::DataAbilityPredicates predicates;
    Uri uri(MEDIALIBRARY_DATA_URI + "/"
        + MEDIA_ALBUMOPRN_QUERYALBUM + "/"
        + SMARTABLUMASSETS_VIEW_NAME);
    predicates.EqualTo(SMARTALBUM_DB_ID, std::to_string(context->objectInfo->GetSmartAlbumId()));
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = context->objectInfo->GetDataAbilityHelper()->Query(uri,
        columns, predicates);
    HiLog::Error(LABEL, "UpdateAlbumCapacity resultSet");
    int32_t albumCapacityIndex = 0, albumCapacity = 1;
    resultSet->GetColumnIndex(SMARTABLUMASSETS_ALBUMCAPACITY, albumCapacityIndex);
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        resultSet->GetInt(albumCapacityIndex, albumCapacity);
        HiLog::Error(LABEL, "UpdateAlbumCapacity albumCapacity = %{public}d", albumCapacity);
        break;
    }
    context->objectInfo->SetAlbumCapacity(albumCapacity);
}
static void JSAddAssetCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;
    if (context->changedRows != -1 && context->changedRows != 0) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
static void JSRemoveAssetCompleteCallback(napi_env env, napi_status status, SmartAlbumNapiAsyncContext *context)
{
    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");
    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->changedRows != -1 && context->changedRows != 0) {
        napi_create_int32(env, context->changedRows, &jsContext->data);
        napi_get_undefined(env, &jsContext->error);
        jsContext->status = true;
    } else {
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}
static napi_value ConvertCommitJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    SmartAlbumNapiAsyncContext &asyncContext)
{
    HiLog::Error(LABEL, "ConvertCommitJSArgsToNative");
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}
napi_value GetJSArgsForAsset(napi_env env, size_t argc,
                             const napi_value argv[],
                             SmartAlbumNapiAsyncContext &asyncContext)
{
    const int32_t refCount = 1;
    napi_value result = nullptr;
    auto context = &asyncContext;
    size_t res = 0;
    char buffer[PATH_MAX];

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_string) {
            napi_get_value_string_utf8(env, argv[i], buffer, PATH_MAX, &res);
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }
    std::string coverUri = string(buffer);
    std::string strRow;
    string::size_type pos = coverUri.find_last_of('/');
    strRow = coverUri.substr(pos + 1);
    HiLog::Error(LABEL, "GetJSArgsForAsset = %{public}d", std::stoi(strRow));
    context->valuesBucket.PutInt(SMARTALBUMMAP_DB_ASSET_ID, std::stoi(strRow));
    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}
napi_value SmartAlbumNapi::JSAddAsset(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSAddAsset");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForAsset(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSAddAsset fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSAddAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                if (context->objectInfo->GetAlbumPrivateType() == TYPE_FAVORITE) {
                    SetFileFav(true, context);
                } else if (context->objectInfo->GetAlbumPrivateType() == TYPE_TRASH) {
                    SetFileTrash(true, context);
                } else {
                    AddAssetNative(context);
                    UpdateAlbumCapacity(context);
                }
            },
            reinterpret_cast<CompleteCallback>(JSAddAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}
napi_value SmartAlbumNapi::JSRemoveAsset(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSRemoveAsset");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_TWO;
    napi_value argv[ARGS_TWO] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ONE || argc == ARGS_TWO), "requires 2 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = GetJSArgsForAsset(env, argc, argv, *asyncContext);
        HiLog::Error(LABEL, "JSRemoveAsset null");
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSRemoveAsset fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSRemoveAsset");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                if (context->objectInfo->GetAlbumPrivateType() == TYPE_FAVORITE) {
                    SetFileFav(false, context);
                } else if (context->objectInfo->GetAlbumPrivateType() == TYPE_TRASH) {
                    SetFileTrash(false, context);
                } else {
                    RemoveAssetNative(context);
                    UpdateAlbumCapacity(context);
                }
            },
            reinterpret_cast<CompleteCallback>(JSRemoveAssetCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}
napi_value SmartAlbumNapi::JSCommitModify(napi_env env, napi_callback_info info)
{
    HiLog::Error(LABEL, "JSCommitModify");
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;
    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, (argc == ARGS_ZERO || argc == ARGS_ONE), "requires 1 parameter maximum");
    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertCommitJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "JSCommitModify fail ");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetAlbumFileAssets");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                CommitModifyNative(*context);
            },
            reinterpret_cast<CompleteCallback>(JSCommitModifyCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}
static void GetFetchOptionsParam(napi_env env, napi_value arg, const SmartAlbumNapiAsyncContext &context, bool &err)
{
    SmartAlbumNapiAsyncContext *asyncContext = const_cast<SmartAlbumNapiAsyncContext *>(&context);
    char buffer[PATH_MAX];
    size_t res;
    uint32_t len = 0;
    napi_value property = nullptr;
    napi_value stringItem = nullptr;
    bool present = false;
    bool boolResult = false;

    napi_has_named_property(env, arg, "selections", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "selections", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->selection = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "order", &present);
    if (present) {
        if (napi_get_named_property(env, arg, "order", &property) != napi_ok
            || napi_get_value_string_utf8(env, property, buffer, PATH_MAX, &res) != napi_ok) {
            HiLog::Error(LABEL, "Could not get the string argument!");
            err = true;
            return;
        } else {
            asyncContext->order = buffer;
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
        present = false;
    }

    napi_has_named_property(env, arg, "selectionArgs", &present);
    if (present && napi_get_named_property(env, arg, "selectionArgs", &property) == napi_ok &&
        napi_is_array(env, property, &boolResult) == napi_ok && boolResult == true) {
        napi_get_array_length(env, property, &len);
        for (size_t i = 0; i < len; i++) {
            napi_get_element(env, property, i, &stringItem);
            napi_get_value_string_utf8(env, stringItem, buffer, PATH_MAX, &res);
            asyncContext->selectionArgs.push_back(std::string(buffer));
            CHECK_IF_EQUAL(memset_s(buffer, PATH_MAX, 0, sizeof(buffer)) == 0, "Memset for buffer failed");
        }
    } else {
        HiLog::Error(LABEL, "Could not get the string argument!");
        err = true;
    }
}

static napi_value ConvertJSArgsToNative(napi_env env, size_t argc, const napi_value argv[],
    SmartAlbumNapiAsyncContext &asyncContext)
{
    string str = "";
    std::vector<string> strArr;
    string order = "";
    bool err = false;
    const int32_t refCount = 1;
    napi_value result;
    auto context = &asyncContext;

    NAPI_ASSERT(env, argv != nullptr, "Argument list is empty");

    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);

        if (i == PARAM0 && valueType == napi_object) {
            GetFetchOptionsParam(env, argv[PARAM0], asyncContext, err);
            if (err) {
                NAPI_ASSERT(env, false, "type mismatch");
            }
        } else if (i == PARAM0 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else if (i == PARAM1 && valueType == napi_function) {
            napi_create_reference(env, argv[i], refCount, &context->callbackRef);
            break;
        } else {
            NAPI_ASSERT(env, false, "type mismatch");
        }
    }

    // Return true napi_value if params are successfully obtained
    napi_get_boolean(env, true, &result);
    return result;
}

static void GetTrashFileAssetsNative(SmartAlbumNapiAsyncContext *context)
{
    HiLog::Error(LABEL, "GetTrashFileAssetsNative in");
    NativeRdb::DataAbilityPredicates predicates;
    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " <> ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), std::to_string(MEDIA_TYPE_ALBUM));
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);

    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultSet =
        context->objectInfo->GetDataAbilityHelper()->Query(uri, columns, predicates);

    context->fetchResult = std::make_unique<FetchResult>(resultSet);
    // context->fetchResult->networkId_ = context->network;
    HiLog::Error(LABEL, "GetTrashFileAssetsNative out");
}

static void GetFavFileAssetsNative(SmartAlbumNapiAsyncContext *context)
{
    HiLog::Error(LABEL, "GetFavFileAssetsNative in");
    NativeRdb::DataAbilityPredicates predicates;
    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? AND " + MEDIA_DATA_DB_IS_FAV + " = ? AND "
        + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(), std::to_string(MEDIA_TYPE_ALBUM));
    context->selectionArgs.insert(context->selectionArgs.begin(), "1");
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);

    std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultSet =
        context->objectInfo->GetDataAbilityHelper()->Query(uri, columns, predicates);

    context->fetchResult = std::make_unique<FetchResult>(resultSet);
    // context->fetchResult->networkId_ = context->network;
    HiLog::Error(LABEL, "GetFavFileAssetsNative out");
}

static void GetFileAssetsNative(SmartAlbumNapiAsyncContext *context)
{
    NativeRdb::DataAbilityPredicates predicates;
    string trashPrefix = MEDIA_DATA_DB_DATE_TRASHED + " = ? AND " + SMARTALBUMMAP_DB_ALBUM_ID + " = ? ";
    MediaLibraryNapiUtils::UpdateFetchOptionSelection(context->selection, trashPrefix);
    context->selectionArgs.insert(context->selectionArgs.begin(),
                                  std::to_string(context->objectInfo->GetSmartAlbumId()));
    context->selectionArgs.insert(context->selectionArgs.begin(), "0");
    predicates.SetWhereClause(context->selection);
    predicates.SetWhereArgs(context->selectionArgs);
    predicates.SetOrder(context->order);
    std::vector<std::string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/"
               + MEDIA_ALBUMOPRN_QUERYALBUM + "/"
               + ASSETMAP_VIEW_NAME);

    std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultSet =
        context->objectInfo->GetDataAbilityHelper()->Query(uri, columns, predicates);

    context->fetchResult = std::make_unique<FetchResult>(move(resultSet));
}

static void JSGetFileAssetsCompleteCallback(napi_env env, napi_status status,
                                            SmartAlbumNapiAsyncContext *context)
{
    napi_value fetchRes = nullptr;

    CHECK_NULL_PTR_RETURN_VOID(context, "Async context is null");

    std::unique_ptr<JSAsyncContextOutput> jsContext = std::make_unique<JSAsyncContextOutput>();
    jsContext->status = false;

    if (context->fetchResult != nullptr) {
        fetchRes = FetchFileResultNapi::CreateFetchFileResult(env, *(context->fetchResult),
                                                              context->objectInfo->sAbilityHelper);
        if (fetchRes == nullptr) {
            HiLog::Error(LABEL, "Failed to get file asset napi object");
            napi_get_undefined(env, &jsContext->data);
            MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_MEM_ALLOCATION,
                "Failed to create js object for FetchFileResult");
        } else {
            jsContext->data = fetchRes;
            napi_get_undefined(env, &jsContext->error);
            jsContext->status = true;
        }
    } else {
        HiLog::Error(LABEL, "No fetch file result found!");
        napi_get_undefined(env, &jsContext->data);
        MediaLibraryNapiUtils::CreateNapiErrorObject(env, jsContext->error, ERR_INVALID_OUTPUT,
                                                     "Failed to obtain fetchFileResult from DB");
    }

    if (context->work != nullptr) {
        MediaLibraryNapiUtils::InvokeJSAsyncMethod(env, context->deferred, context->callbackRef,
                                                   context->work, *jsContext);
    }
    delete context;
}

napi_value SmartAlbumNapi::JSGetSmartAlbumFileAssets(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value result = nullptr;
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = {0};
    napi_value thisVar = nullptr;
    napi_value resource = nullptr;

    GET_JS_ARGS(env, info, argc, argv, thisVar);
    NAPI_ASSERT(env, ((argc == ARGS_ZERO) || (argc == ARGS_ONE) || (argc == ARGS_TWO)),
                "requires 2 parameter maximum");

    napi_get_undefined(env, &result);
    std::unique_ptr<SmartAlbumNapiAsyncContext> asyncContext = std::make_unique<SmartAlbumNapiAsyncContext>();

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&asyncContext->objectInfo));
    if (status == napi_ok && asyncContext->objectInfo != nullptr) {
        result = ConvertJSArgsToNative(env, argc, argv, *asyncContext);
        CHECK_NULL_PTR_RETURN_UNDEFINED(env, result, result, "Failed to obtain arguments");

        NAPI_CREATE_PROMISE(env, asyncContext->callbackRef, asyncContext->deferred, result);
        NAPI_CREATE_RESOURCE_NAME(env, resource, "JSGetSmartAlbumFileAssets");

        status = napi_create_async_work(
            env, nullptr, resource, [](napi_env env, void* data) {
                    auto context = static_cast<SmartAlbumNapiAsyncContext*>(data);
                    if (context->objectInfo->GetAlbumPrivateType() == TYPE_FAVORITE) {
                        GetFavFileAssetsNative(context);
                    } else if (context->objectInfo->GetAlbumPrivateType() == TYPE_TRASH) {
                        GetTrashFileAssetsNative(context);
                    } else {
                        GetFileAssetsNative(context);
                    }
            },
            reinterpret_cast<CompleteCallback>(JSGetFileAssetsCompleteCallback),
            static_cast<void*>(asyncContext.get()), &asyncContext->work);
        if (status != napi_ok) {
            napi_get_undefined(env, &result);
        } else {
            napi_queue_async_work(env, asyncContext->work);
            asyncContext.release();
        }
    }

    return result;
}
} // namespace Media
} // namespace OHOS

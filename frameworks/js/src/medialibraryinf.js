/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

const medialibrary = requireInternal('multimedia.mediaLibrary');
const featureAbility = requireNapi('ability.featureAbility');

async function startMediaSelect(option, asyncCallback)
{
    console.log("MediaLibrary startMediaSelectInner param num " + arguments.length);
    console.log("MediaLibrary startMediaSelectInner param " + JSON.stringify(option));
    let select = "singleselect"
    let parameter = {
        want:
        {
            action: "ohos.want.action.photoPicker",
            type: select,
            parameters: {
                uri : select,
                filterMediaType: "FILTER_MEDIA_TYPE_ALL",
                maxSelectCount: 1,
            }
        },
        action: "ohos.want.action.photoPicker",
        type: select,
        parameters: {
            uri : select,
            filterMediaType: "FILTER_MEDIA_TYPE_ALL",
            maxSelectCount: 1,
        }
    }
    if (option != undefined && typeof option == 'object') {
        if (option.count != undefined && option.count > 1) {
            parameter.want.type = "multipleselect";
            parameter.want.parameters.uri = "multipleselect";
            parameter.want.parameters.maxSelectCount = option.count;
            parameter.type = "multipleselect";
            parameter.parameters.uri = "multipleselect";
            parameter.parameters.maxSelectCount = option.count;
        }
        if (option.type != undefined) {
            parameter.want.parameters.filterMediaType = option.type;
            parameter.parameters.filterMediaType = option.type;
        }
    }
    if (arguments.length == 2 && typeof asyncCallback != "function") {
        console.log("MediaLibrary startMediaSelectInner callback invalid");
        throw Error("invalid callback")
    }
    console.log("MediaLibrary startMediaSelectInner parameter " + JSON.stringify(parameter));
    let result = await featureAbility.startAbilityForResult(parameter)
    console.log("MediaLibrary startMediaSelectInner result " +JSON.stringify(result));
    let uri = result.want.parameters["select-item-list"]
    if (arguments.length == 2 && typeof asyncCallback == "function") {
        console.log("MediaLibrary startMediaSelectInner callback " + uri);
        return asyncCallback(result.resultCode, uri)
    }
    return new Promise((resolve, reject) => {
        if (result.resultCode == 0) {
            console.log("MediaLibrary startMediaSelectInner promise " + uri);
            resolve(uri)
        } else {
            console.log("MediaLibrary startMediaSelectInner err " + result.resultCode);
            reject(result.resultCode)
        }
    })
}

function getMediaLibrary(context)
{
    let media = medialibrary.getMediaLibrary(context)
    console.log("MediaLibrary getMediaLibrary inner ");
    if (media != undefined) {
        console.log("MediaLibrary getMediaLibrary inner add startMediaSelect");
        media.startMediaSelect = startMediaSelect;
    }
    return media;
}

function getScannerInstance(context)
{
    console.log("MediaLibrary getScannerInstance js caller ");
    let instance = medialibrary.getScannerInstance(context)
    return instance;
}

export default {
    getMediaLibrary: getMediaLibrary,
    getScannerInstance: getScannerInstance,
    MediaType: medialibrary.MediaType,
    FileKey: medialibrary.FileKey,
    DirectoryType: medialibrary.DirectoryType,
    PrivateAlbumType: medialibrary.PrivateAlbumType,
}
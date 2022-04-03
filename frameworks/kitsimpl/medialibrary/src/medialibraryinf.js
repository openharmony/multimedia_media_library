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

const medialibrary = requireInternal('multimedia.medialibrary');
const featureAbility = requireNapi('ability.featureAbility');

async function startMediaSelect(option, asyncCallback)
{
    console.log("MediaLibrary startMediaSelectInner param len " + arguments.length);
    console.log("MediaLibrary startMediaSelectInner param " + JSON.stringify(option));
    let select = "singleselect"
    if (option.count > 1) {
        select = "multipleselect"
    }
    let parameter = {
        want:
        {
            parameters: {uri : select},
            bundleName: "com.ohos.photos",
            abilityName: "com.ohos.photos.MainAbility",
        },
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
    let obj = medialibrary.getMediaLibrary(context)
    console.log("MediaLibrary getMediaLibrary inner ");
    if (obj != undefined) {
        console.log("MediaLibrary getMediaLibrary inner add startMediaSelect");
        obj.startMediaSelect = startMediaSelect;
    }
    return obj;
}

export default {
    startMediaSelect: startMediaSelect,
    getMediaLibrary: getMediaLibrary,
}
/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

var __decorate = this && this.__decorate || function (e, o, t, i) {
    var n, r = arguments.length, l = r < 3 ? o : null === i ? i = Object.getOwnPropertyDescriptor(o, t) : i;
    if ('object' === typeof Reflect && 'function' === typeof Reflect.decorate) {
        l = Reflect.decorate(e, o, t, i);
    } else {
        for (var s = e.length - 1; s >= 0; s--) {
            (n = e[s]) && (l = (r < 3 ? n(l) : r > 3 ? n(o, t, l) : n(o, t)) || l);
        }
    }
    return r > 3 && l && Object.defineProperty(o, t, l), l;
};
const fs = requireNapi('file.fs');
const fileUri = requireNapi('file.fileuri');
const bundleManager = requireNapi('bundle.bundleManager');
const photoAccessHelper = requireNapi('file.photoAccessHelper');
const FILTER_MEDIA_TYPE_ALL = 'FILTER_MEDIA_TYPE_ALL';
const FILTER_MEDIA_TYPE_IMAGE = 'FILTER_MEDIA_TYPE_IMAGE';
const FILTER_MEDIA_TYPE_VIDEO = 'FILTER_MEDIA_TYPE_VIDEO';

export class PhotoPickerComponent extends ViewPU {
    constructor(e, o, t, i = -1, n = void 0) {
        super(e, t, i);
        'function' === typeof n && (this.paramsGenerator_ = n);
        this.pickerOptions = void 0;
        this.onSelect = void 0;
        this.onDeselect = void 0;
        this.onItemClicked = void 0;
        this.onEnterPhotoBrowser = void 0;
        this.onExitPhotoBrowser = void 0;
        this.onPickerControllerReady = void 0;
        this.onPhotoBrowserChanged = void 0;
        this.onSelectedItemsDeleted = void 0;
        this.onExceedMaxSelected = void 0;
        this.onCurrentAlbumDeleted = void 0;
        this.onVideoPlayStateChanged = void 0;
        this.__pickerController = new SynchedPropertyNesedObjectPU(o.pickerController, this, 'pickerController');
        this.proxy = void 0;
        this.__revokeIndex = new ObservedPropertySimplePU(0, this, 'revokeIndex');
        this.setInitiallyProvidedValue(o);
        this.declareWatch('pickerController', this.onChanged);
    }

    setInitiallyProvidedValue(e) {
        void 0 !== e.pickerOptions && (this.pickerOptions = e.pickerOptions);
        void 0 !== e.onSelect && (this.onSelect = e.onSelect);
        void 0 !== e.onDeselect && (this.onDeselect = e.onDeselect);
        void 0 !== e.onItemClicked && (this.onItemClicked = e.onItemClicked);
        void 0 !== e.onEnterPhotoBrowser && (this.onEnterPhotoBrowser = e.onEnterPhotoBrowser);
        void 0 !== e.onExitPhotoBrowser && (this.onExitPhotoBrowser = e.onExitPhotoBrowser);
        void 0 !== e.onPhotoBrowserChanged && (this.onPhotoBrowserChanged = e.onPhotoBrowserChanged);
        void 0 !== e.onPickerControllerReady && (this.onPickerControllerReady = e.onPickerControllerReady);
        void 0 !== e.onSelectedItemsDeleted && (this.onSelectedItemsDeleted = e.onSelectedItemsDeleted);
        void 0 !== e.onExceedMaxSelected && (this.onExceedMaxSelected = e.onExceedMaxSelected);
        void 0 !== e.onCurrentAlbumDeleted && (this.onCurrentAlbumDeleted = e.onCurrentAlbumDeleted);
        void 0 !== e.onVideoPlayStateChanged && (this.onVideoPlayStateChanged = e.onVideoPlayStateChanged);
        this.__pickerController.set(e.pickerController);
        void 0 !== e.proxy && (this.proxy = e.proxy);
        if (e.revokeIndex !== undefined) {
            this.revokeIndex = e.revokeIndex;
        }
    }

    updateStateVars(e) {
        this.__pickerController.set(e.pickerController);
    }

    purgeVariableDependenciesOnElmtId(e) {
        this.__pickerController.purgeDependencyOnElmtId(e);
        this.__revokeIndex.purgeDependencyOnElmtId(e);
    }

    aboutToBeDeleted() {
        this.__pickerController.aboutToBeDeleted();
        this.__revokeIndex.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    get pickerController() {
        return this.__pickerController.get();
    }

    get revokeIndex() {
        return this.__revokeIndex.get();
    }

    set revokeIndex(newValue) {
        return this.__revokeIndex.set();
    }

    onChanged() {
        var e;
        if (!this.proxy) {
            return;
        }
        let o = null === (e = this.pickerController) || void 0 === e ? void 0 : e.data;
        if (null == o ? void 0 : o.has('SET_SELECTED_URIS')) {
            this.proxy.send({ selectUris: null == o ? void 0 : o.get('SET_SELECTED_URIS') });
            console.info('PhotoPickerComponent onChanged: SET_SELECTED_URIS');
        } else if (null == o ? void 0 : o.has('SET_ALBUM_URI')) {
            this.proxy.send({ albumUri: null == o ? void 0 : o.get('SET_ALBUM_URI') });
            console.info('PhotoPickerComponent onChanged: SET_ALBUM_URI');
        } else if (null == o ? void 0 : o.has('SET_MAX_SELECT_COUNT')) {
            this.onSetMaxSelectCount(o);
        } else if (null == o ? void 0 : o.has('SET_PHOTO_BROWSER_ITEM')) {
            this.onSetPhotoBrowserItem(o);
        } else if (null == o ? void 0 : o.has('EXIT_PHOTO_BROWSER')) {
            this.handleExitPhotoBrowser();
        } else {
            this.otherOnChange(o);
        }
    }

    otherOnChange(o) {
        if (null == o ? void 0 : o.has('SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY')) {
            this.onSetPhotoBrowserUIElementVisibility(o);
        } else if (null == o ? void 0 : o.has('CREATE_URI')) {
            this.onCreateUri(o);
            console.info('PhotoPickerComponent onChanged: CREATE_URI');
        } else if (null == o ? void 0 : o.has('REPLACE_URI')) {
            this.onReplaceUri(o);
            console.info('PhotoPickerComponent onChanged: REPLACE_URI');
        } else if (null == o ? void 0 : o.has('SAVE_REPLACE_PHOTO_ASSETS')) {
            this.onSaveTrustedPhotoAssets(o);
            console.info('PhotoPickerComponent onChanged: SAVE_REPLACE_PHOTO_ASSETS');
        } else {
            console.info('PhotoPickerComponent onChanged: other case');
        }
    }

    onSetMaxSelectCount(o) {
        let e = null == o ? void 0 : o.get('SET_MAX_SELECT_COUNT');
        let t = null == e ? void 0 : e.data;
        this.proxy.send({
            totalCount: null == t ? void 0 : t.get(MaxCountType.TOTAL_MAX_COUNT),
            photoCount: null == t ? void 0 : t.get(MaxCountType.PHOTO_MAX_COUNT),
            videoCount: null == t ? void 0 : t.get(MaxCountType.VIDEO_MAX_COUNT)
        });
        console.info('PhotoPickerComponent onChanged: SET_MAX_SELECT_COUNT');
    }

    onSetPhotoBrowserItem(o) {
        let e = null == o ? void 0 : o.get('SET_PHOTO_BROWSER_ITEM');
        this.proxy.send({ 
            itemUri: null == e ? void 0 : e.uri, 
            photoBrowserRange: null == e ? void 0 : e.photoBrowserRange 
        });
        console.info('PhotoPickerComponent onChanged: SET_PHOTO_BROWSER_ITEM');
    }

    handleExitPhotoBrowser() {
        this.proxy.send({ exitPhotoBrowser: true });
        console.info('PhotoPickerComponent onChanged: EXIT_PHOTO_BROWSER');
    }

    onSetPhotoBrowserUIElementVisibility(o) {
        let e = null == o ? void 0 : o.get('SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY');
        this.proxy.send({
            elements: null == e ? void 0 : e.elements,
            isVisible: null == e ? void 0 : e.isVisible
        });
        console.info('PhotoPickerComponent onChanged: SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY');
    }

    onCreateUri(o) {
        let e = null == o ? void 0 : o.get('CREATE_URI');
        this.proxy.send({
            selectedMediaUri: null == e ? void 0 : e[0],
            createUri: null == e ? void 0 : e[1],
            date: null == e ? void 0 : e[2]
        });
        console.info('PhotoPickerComponent onChanged CREATE_URI ');
    }

    onReplaceUri(o) {
        let e = null == o ? void 0 : o.get('REPLACE_URI');
        this.proxy.send({
            oriUri: null == e ? void 0 : e[0],
            replaceUri: null == e ? void 0 : e[1],
            date: null == e ? void 0 : e[2]
        });
        console.info('PhotoPickerComponent onChanged REPLACE_URI');
    }

    onSaveTrustedPhotoAssets(o) {
        let e = null == o ? void 0 : o.get('SAVE_REPLACE_PHOTO_ASSETS');
        this.proxy.send({
            replaceUris: null == e ? void 0 : e[0],
            config: null == e ? void 0 : e[1],
            saveMode: null == e ? void 0 : e[2],
            appName: null == e ? void 0 : e[3],
            date: null == e ? void 0 : e[4]
        });
        console.info('PhotoPickerComponent onChanged SAVE_REPLACE_PHOTO_ASSETS');
    }

    initialRender() {
        this.observeComponentCreation2(((e, o) => {
            Row.create();
            Row.height('100%');
        }), Row);
        this.observeComponentCreation2(((e, o) => {
            Column.create();
            Column.width('100%');
        }), Column);
        this.observeComponentCreation2(((e, o) => {
            var t, i, n, r, l, s, c, p, a, d, h, E, C, T, m, P, _, b, d;
            SecurityUIExtensionComponent.create({
                parameters: {
                    errorRevokeIndex: this.revokeIndex,
                    'ability.want.params.uiExtensionTargetType': 'photoPicker',
                    uri: 'multipleselect',
                    targetPage: 'photoPage',
                    filterMediaType: this.convertMIMETypeToFilterType(null === (t = this.pickerOptions) || void 0 === t ? void 0 : t.MIMEType),
                    maxSelectNumber: null === (i = this.pickerOptions) || void 0 === i ? void 0 : i.maxSelectNumber,
                    isPhotoTakingSupported: null === (n = this.pickerOptions) || void 0 === n ? void 0 : n.isPhotoTakingSupported,
                    isEditSupported: !1,
                    recommendationOptions: null === (r = this.pickerOptions) || void 0 === r ? void 0 : r.recommendationOptions,
                    preselectedUri: null === (l = this.pickerOptions) || void 0 === l ? void 0 : l.preselectedUris,
                    isFromPickerView: !0,
                    isNeedActionBar: !1,
                    isNeedSelectBar: !1,
                    isSearchSupported: null === (s = this.pickerOptions) || void 0 === s ? void 0 : s.isSearchSupported,
                    checkBoxColor: null === (c = this.pickerOptions) || void 0 === c ? void 0 : c.checkBoxColor,
                    backgroundColor: null === (p = this.pickerOptions) || void 0 === p ? void 0 : p.backgroundColor,
                    checkboxTextColor: null === (a = this.pickerOptions) || void 0 === a ? void 0 : a.checkboxTextColor,
                    photoBrowserBackgroundColorMode: null === (d = this.pickerOptions) || void 0 === d ? void 0 : d.photoBrowserBackgroundColorMode,
                    isRepeatSelectSupported: null === (h = this.pickerOptions) || void 0 === h ? void 0 : h.isRepeatSelectSupported,
                    maxSelectedReminderMode: null === (E = this.pickerOptions) || void 0 === E ? void 0 : E.maxSelectedReminderMode,
                    orientation: null === (C = this.pickerOptions) || void 0 === C ? void 0 : C.orientation,
                    selectMode: null === (T = this.pickerOptions) || void 0 === T ? void 0 : T.selectMode,
                    maxPhotoSelectNumber: null === (m = this.pickerOptions) || void 0 === m ? void 0 : m.maxPhotoSelectNumber,
                    maxVideoSelectNumber: null === (P = this.pickerOptions) || void 0 === P ? void 0 : P.maxVideoSelectNumber,
                    isOnItemClickedSet: !!this.onItemClicked,
                    isPreviewForSingleSelectionSupported: null === (_ = this.pickerOptions) || void 0 === _ ? void 0 : _.isPreviewForSingleSelectionSupported,
                    isSlidingSelectionSupported: null === (b = this.pickerOptions) || void 0 === b ? void 0 : b.isSlidingSelectionSupported,
                    photoBrowserCheckboxPosition: null === (d = this.pickerOptions) || void 0 === d ? void 0 : d.photoBrowserCheckboxPosition,
                    gridMargin: null === (_ = this.pickerOptions) || void 0 === _ ? void 0 : _.gridMargin,
                    photoBrowserMargin: null === (_ = this.pickerOptions) || void 0 === _ ? void 0 : _.photoBrowserMargin
                }
            });
            SecurityUIExtensionComponent.height('100%');
            SecurityUIExtensionComponent.width('100%');
            SecurityUIExtensionComponent.onRemoteReady((e => {
                this.proxy = e;
                console.info('PhotoPickerComponent onRemoteReady');
            }));
            SecurityUIExtensionComponent.onReceive((e => {
                let o = e;
                this.handleOnReceive(o);
            }));
            SecurityUIExtensionComponent.onError(((error) => {
                console.info('PhotoPickerComponent onError: ' + JSON.stringify(error));
                console.info('PhotoPickerComponent revokeIndex: ' + this.revokeIndex);
                if (error.code === 100014 && this.revokeIndex < 5) {
                    this.revokeIndex++;
                }
            }));
        }), SecurityUIExtensionComponent);
        Column.pop();
        Row.pop();
    }

    handleOnReceive(e) {
        let o = e.dataType;
        console.info('PhotoPickerComponent onReceive: dataType = ' + o);
        if ('selectOrDeselect' === o) {
            this.handleSelectOrDeselect(e);
        } else if ('itemClick' === o) {
            this.handleItemClick(e); 
        } else if ('onPhotoBrowserStateChanged' === o) {
            this.handleEnterOrExitPhotoBrowser(e);
        } else if ('remoteReady' === o) {
            if (this.onPickerControllerReady) {
                this.onPickerControllerReady();
                console.info('PhotoPickerComponent onReceive: onPickerControllerReady');
            }
        } else if ('replaceCallback' === o) {
            this.handleReplaceCallback(e);
        } else if ('createCallback' === o) {
            this.handleCreateCallback(e);
        } else if ('saveCallback' === o) {
            this.handleSaveCallback(e);
        } else if ('onPhotoBrowserChanged' === o) {
            this.handlePhotoBrowserChange(e);
        } else if ('onVideoPlayStateChanged' === o) {
            this.handleVideoPlayStateChanged(e);
        } else {
            this.handleOtherOnReceive(e);
            console.info('PhotoPickerComponent onReceive: other case');
        }
        console.info('PhotoPickerComponent onReceive' + JSON.stringify(e));
    }

    handleOtherOnReceive(e) {
        let o = e.dataType;
        if ('exceedMaxSelected' === o) {
            if (this.onExceedMaxSelected) {
                this.onExceedMaxSelected(e.maxCountType);
            }
        } else if ('selectedItemsDeleted' === o) {
            if (this.onSelectedItemsDeleted) {
                this.onSelectedItemsDeleted(e.selectedItemInfos);
            }
        } else if ('currentAlbumDeleted' === o) {
            if (this.onCurrentAlbumDeleted) {
                this.onCurrentAlbumDeleted();
            }
        } else {
            console.info('PhotoPickerComponent onReceive: other case');
        }
    }

    handleSelectOrDeselect(e) {
        if (e.isSelect) {
            if (this.onSelect) {
                this.onSelect(e['select-item-list']);
                console.info('PhotoPickerComponent onReceive: onSelect');
            }
        } else if (this.onDeselect) {
            this.onDeselect(e['select-item-list']);
            console.info('PhotoPickerComponent onReceive: onDeselect');
        }
    }

    handleItemClick(e) {
        if (this.onItemClicked) {
            let o = ClickType.SELECTED;
            let t = e.clickType;
            'select' === t ? o = ClickType.SELECTED : 'deselect' === t ? o = ClickType.DESELECTED : console.info('PhotoPickerComponent onReceive: other clickType');
            let i = new ItemInfo;
            let n = e.itemType;
            'thumbnail' === n ? i.itemType = ItemType.THUMBNAIL : 'camera' === n ? i.itemType = ItemType.CAMERA : console.info('PhotoPickerComponent onReceive: other itemType');
            i.uri = e.uri;
            i.mimeType = e.mimeType;
            i.width = e.width;
            i.height = e.height;
            i.size = e.size;
            i.duration = e.duration;
            let r = this.onItemClicked(i, o);
            console.info('PhotoPickerComponent onReceive: onItemClicked = ' + o);
            if (this.proxy) {
                if ('thumbnail' === n && o === ClickType.SELECTED) {
                    this.proxy.send({ clickConfirm: i.uri, isConfirm: r });
                    console.info('PhotoPickerComponent onReceive: click confirm: uri = ' + i.uri + 'isConfirm = ' + r);
                }
                if ('camera' === n) {
                    this.proxy.send({ enterCamera: r });
                    console.info('PhotoPickerComponent onReceive: enter camera ' + r);
                }
            }
        }
    }

    handleEnterOrExitPhotoBrowser(e) {
        let o = e.isEnter;
        let t = new PhotoBrowserInfo;
        t.animatorParams = new AnimatorParams;
        t.animatorParams.duration = e.duration;
        t.animatorParams.curve = e.curve;
        o ? this.onEnterPhotoBrowser && this.onEnterPhotoBrowser(t) : this.onExitPhotoBrowser && this.onExitPhotoBrowser(t);
        console.info('PhotoPickerComponent onReceive: onPhotoBrowserStateChanged = ' + o);
    }

    handlePhotoBrowserChange(e) {
        let o = new BaseItemInfo();
        o.uri = e.uri;
        if (this.onPhotoBrowserChanged) {
            this.onPhotoBrowserChanged(o);
        }
        console.info('PhotoPickerComponent onReceive: onPhotoBrowserChanged = ' + o.uri);
    }

    handleVideoPlayStateChanged(e) {
        if (this.onVideoPlayStateChanged) {
            this.onVideoPlayStateChanged(e.state);
            console.info('PhotoPickerComponent onReceive: onVideoPlayStateChanged = ' + JSON.stringify(e));
        }
    }

    handleCreateCallback(e) {
        this.pickerController.actionCreateCallback(e.grantUri, e.date, e.code, e.message);
        console.info('PhotoPickerComponent onReceive: handleCreateCallback');
    }

    handleReplaceCallback(e) {
        this.pickerController.actionReplaceCallback(e.date, {'name': '', 'code': e.code, 'message': e.message});
        console.info('PhotoPickerComponent onReceive: handleReplaceCallback');
    }

    handleSaveCallback(e) {
        this.pickerController.actionSaveCallback(e.date, {'name': '', 'code': e.code, 'message': e.message}, e.data);
        console.info('PhotoPickerComponent onReceive: handleSaveCallback');
    }

    convertMIMETypeToFilterType(e) {
        let o;
        o = e === photoAccessHelper.PhotoViewMIMETypes.IMAGE_TYPE ?
            FILTER_MEDIA_TYPE_IMAGE : e === photoAccessHelper.PhotoViewMIMETypes.VIDEO_TYPE ?
            FILTER_MEDIA_TYPE_VIDEO : FILTER_MEDIA_TYPE_ALL;
        console.info('PhotoPickerComponent convertMIMETypeToFilterType' + JSON.stringify(o));
        return o;
    }

    rerender() {
        this.updateDirtyElements();
    }
}
let PickerController = class {
    constructor() {
        this.replaceCallbackMap = new Map();
        this.saveCallbackMap = new Map();
        this.createCallbackMap = new Map();
    }
    setData(e, o) {
        if (o === undefined) {
            return;
        }
        if (e === DataType.SET_SELECTED_URIS) {
            if (o instanceof Array) {
                let e = o;
                if (e) {
                    this.data = new Map([['SET_SELECTED_URIS', [...e]]]);
                    console.info('PhotoPickerComponent SET_SELECTED_URIS' + JSON.stringify(e));
                }
            }
        } else if (e === DataType.SET_ALBUM_URI) {
            let e = o;
            if (e !== undefined) {
                this.data = new Map([['SET_ALBUM_URI', e]]);
                console.info('PhotoPickerComponent SET_ALBUM_URI' + JSON.stringify(e));
            }
        } else {
            console.info('PhotoPickerComponent setData: other case');
        }
    }

    setMaxSelected(e) {
        if (e) {
            this.data = new Map([['SET_MAX_SELECT_COUNT', e]]);
            console.info('PhotoPickerComponent SET_MAX_SELECT_COUNT' + JSON.stringify(e));
        }
    }

    setPhotoBrowserItem(e, o) {
        let l = new PhotoBrowserRangeInfo;
        l.uri = e;
        let m = o ? o : PhotoBrowserRange.ALL;
        l.photoBrowserRange = m;
        this.data = new Map([['SET_PHOTO_BROWSER_ITEM', l]]);
        console.info('PhotoPickerComponent SET_PHOTO_BROWSER_ITEM ' + JSON.stringify(l));
    }

    exitPhotoBrowser() {
        this.data = new Map([['EXIT_PHOTO_BROWSER', true]]);
        console.info('PhotoPickerComponent EXIT_PHOTO_BROWSER ');
    }

    async getAppName() {
        let flags = bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_ABILITY |
            bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_HAP_MODULE |
            bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_SIGNATURE_INFO |
            bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION;
        let c2 = bundleManager.getBundleInfoForSelfSync(flags);
        let labelId = c2.appInfo.labelId;
        let appName = '';
        let moduleName = '';
        for (let d2 of c2.hapModulesInfo) {
            if (labelId === d2.labelId) {
                moduleName = d2.name;
            }
        }
        appName = await getContext(this).createModuleContext(moduleName).resourceManager.getStringValue(labelId);
        return appName;
    }

    replacePhotoPickerPreview(e, o, callback) {
        try {
            let fd = fs.openSync(o).fd;
            fs.close(fd);
        } catch (err) {
            callback({'code': 13900002, 'message': 'No such file', name: ''});
            return;
        }
        let date = Math.random();
        this.data = new Map([['CREATE_URI', [e, o, date]]]);
        this.createCallbackMap.set(date, (grantUri, code, message)=>{
            if (code !== 0) {
                callback({'code': code, 'message': message, name: ''});
                return;
            }
            let createFd = 0;
            let replaceFd = 0;
            try {
                createFd = fs.openSync(grantUri, fs.OpenMode.READ_WRITE).fd;
                replaceFd = fs.openSync(o, fs.OpenMode.READ_ONLY).fd;
                fs.copyFileSync(replaceFd, createFd);
                this.data = new Map([['REPLACE_URI', [e, grantUri, date]]]);
                this.replaceCallbackMap.set(date, callback);
            } catch (err) {
                callback({'code': 14000011, 'message': 'System inner fail', name: ''});
            } finally {
                fs.close(createFd);
                fs.close(replaceFd);
            }
        });
    }

    saveTrustedPhotoAssets(e, callback, config, saveMode) {
        if (!e || e.length === 0) {
            callback({'code': 14000002, 'message': 'Invalid URI', name: ''}, []);
            return;
        }
        this.getAppName().then((appName) => {
            let date = Math.random();
            this.data = new Map([['SAVE_REPLACE_PHOTO_ASSETS', [e, config, saveMode, appName, date]]]);
            this.saveCallbackMap.set(date, callback);
            console.info('PhotoPickerComponent SAVE_TRUSTED_PHOTO_ASSETS ');
        });
    }

    actionCreateCallback(grantUri, date, code, message) {
        if (this.createCallbackMap.has(date)) {
            let callback = this.createCallbackMap.get(date);
            if (callback) {
                callback(grantUri, code, message);
                this.createCallbackMap.delete(date);
            }
        }
    }

    actionReplaceCallback(date, err) {
        if (this.replaceCallbackMap.has(date)) {
            let callback = this.replaceCallbackMap.get(date);
            if (callback) {
                callback(err);
                this.replaceCallbackMap.delete(date);
            }
        }
    }
    
    actionSaveCallback(date, err, data) {
        if (this.saveCallbackMap.has(date)) {
            let callback = this.saveCallbackMap.get(date);
            if (callback) {
                callback(err, data);
                this.saveCallbackMap.delete(date);
            }
        }
    }

    setPhotoBrowserUIElementVisibility(e, o) {
        let m = new PhotoBrowserUIElementVisibility;
        m.elements = e;
        m.isVisible = o;
        this.data = new Map([['SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY', m]]);
        console.info('PhotoPickerComponent SET_PHOTO_BROWSER_UI_ELEMENT_VISIBILITY ' + JSON.stringify(m));
    }
};
PickerController = __decorate([Observed], PickerController);

export class PickerOptions extends photoAccessHelper.BaseSelectOptions {
}

export class BaseItemInfo {
}

export class ItemInfo extends BaseItemInfo {
}

export class PhotoBrowserInfo {
}

export class AnimatorParams {
}

export class MaxSelected {
}

class PhotoBrowserRangeInfo {
}

class PhotoBrowserUIElementVisibility {
}

export var DataType;
!function(e) {
    e[e.SET_SELECTED_URIS = 1] = 'SET_SELECTED_URIS';
    e[e.SET_ALBUM_URI = 2] = 'SET_ALBUM_URI';
}(DataType || (DataType = {}));

export var ItemType;
!function(e) {
    e[e.THUMBNAIL = 0] = 'THUMBNAIL';
    e[e.CAMERA = 1] = 'CAMERA';
}(ItemType || (ItemType = {}));

export var ClickType;
!function(e) {
    e[e.SELECTED = 0] = 'SELECTED';
    e[e.DESELECTED = 1] = 'DESELECTED';
}(ClickType || (ClickType = {}));

export var PickerOrientation;
!function(e) {
    e[e.VERTICAL = 0] = 'VERTICAL';
    e[e.HORIZONTAL = 1] = 'HORIZONTAL';
}(PickerOrientation || (PickerOrientation = {}));

export var SelectMode;
!function(e) {
    e[e.SINGLE_SELECT = 0] = 'SINGLE_SELECT';
    e[e.MULTI_SELECT = 1] = 'MULTI_SELECT';
}(SelectMode || (SelectMode = {}));

export var PickerColorMode;
!function(e) {
    e[e.AUTO = 0] = 'AUTO';
    e[e.LIGHT = 1] = 'LIGHT';
    e[e.DARK = 2] = 'DARK';
}(PickerColorMode || (PickerColorMode = {}));

export var ReminderMode;
!function(e) {
    e[e.NONE = 0] = 'NONE';
    e[e.TOAST = 1] = 'TOAST';
    e[e.MASK = 2] = 'MASK';
}(ReminderMode || (ReminderMode = {}));

export var MaxCountType;
!function(e) {
    e[e.TOTAL_MAX_COUNT = 0] = 'TOTAL_MAX_COUNT';
    e[e.PHOTO_MAX_COUNT = 1] = 'PHOTO_MAX_COUNT';
    e[e.VIDEO_MAX_COUNT = 2] = 'VIDEO_MAX_COUNT';
}(MaxCountType || (MaxCountType = {}));

export var PhotoBrowserRange;
!function(e) {
    e[e.ALL = 0] = 'ALL';
    e[e.SELECTED_ONLY = 1] = 'SELECTED_ONLY';
}(PhotoBrowserRange || (PhotoBrowserRange = {}));

export var PhotoBrowserUIElement;
!function(e) {
    e[e.CHECKBOX = 0] = 'CHECKBOX';
    e[e.BACK_BUTTON = 1] = 'BACK_BUTTON';
}(PhotoBrowserUIElement || (PhotoBrowserUIElement = {}));

export var VideoPlayerState;
!function(e) {
    e[e.PLAYING = 0] = 'PLAYING';
    e[e.PAUSED = 1] = 'PAUSED';
    e[e.STOPPED = 2] = 'STOPPED';
    e[e.SEEK_START = 3] = 'SEEK_START';
    e[e.SEEK_FINISH = 4] = 'SEEK_FINISH';
}(VideoPlayerState || (VideoPlayerState = {}));

export var SaveMode;
!function(e) {
    e[e.SAVE_AS = 0] = 'SAVE_AS';
    e[e.OVERWRITE = 1] = 'OVERWRITE';
}(SaveMode || (SaveMode = {}));

export default { PhotoPickerComponent, PickerController, PickerOptions, DataType, BaseItemInfo, ItemInfo, PhotoBrowserInfo, AnimatorParams,
    MaxSelected, ItemType, ClickType, PickerOrientation, SelectMode, PickerColorMode, ReminderMode, MaxCountType, PhotoBrowserRange, PhotoBrowserUIElement,
    VideoPlayerState, SaveMode};
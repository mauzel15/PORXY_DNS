#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Author  : qiusong_chen@foxmail.com

from flask import Flask, render_template, request, make_response, jsonify
from PORXY_DNS import RedisHandler

app=Flask(__name__)



@app.route('/')
def index():
    return render_template('index.html')

@app.route("/post/clean", methods=['POST'])
def clean():
    data = request.get_json()
    print "###########################", data
    if data["index"] != '0':
        record = "%s_%s." %(data["type"], data["record"])
        try:
            RedisHandler(host="127.0.0.1",port="6379", name="delete", passwd="111111").delete(record)
            return make_response(jsonify({'msg': '清除成功'}), 200)
        except:
            return make_response(jsonify({'msg': '清除成功'}), 200)

    else:
        return make_response(jsonify({'msg': '没有选择DNS记录类型'}), 500)

if __name__ == '__main__':
    app.run(host="10.1.1.2", port=8090, use_reloader=True, debug=True)

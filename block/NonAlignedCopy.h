#ifndef NONALIGNEDCOPYHANDLER_H
#define NONALIGNEDCOPYHANDLER_H

/*
 * Copyright (C) 2014 
 * Author: Sandeep Joshi
 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

    // Purpose of this structure is to encapsulate calculations done during non-aligned IO
    // .e.g you want to read len=8k from start=6K but blockSize=4K
    // this will require reading 3 chunks of blockSize
    // first chunk has to be read from start=6K, len=2K
    // second chunk has to be read from start=8K, len=4k
    // third chunk has to be read from start=12k, len=2K

    // the NonAlignedCopyNext() func will return these values once you initialize it with (start=6K, len=8K, blockSize=4K)

typedef struct NonAlignedCopy
{
    // need signed number "ssize_t" to check negative below
    ssize_t start_;
    ssize_t len_;
    ssize_t blockSize_;
    ssize_t cur_;
}NonAlignedCopy;

void NonAlignedCopyInit(NonAlignedCopy* thisptr, ssize_t start, ssize_t len, ssize_t blockSize);
int NonAlignedCopyIsValid(NonAlignedCopy* thisptr);
int NonAlignedCopyNext(NonAlignedCopy* thisptr, ssize_t* retOffset, ssize_t* retSize);

void NonAlignedCopyInit(NonAlignedCopy* thisptr, ssize_t start, ssize_t len, ssize_t blockSize) 
{
    thisptr->start_ = start;
    thisptr->len_ = len; 
    thisptr->blockSize_ = blockSize;
    thisptr->cur_ = start;
}

int NonAlignedCopyIsValid(NonAlignedCopy* thisptr) 
{
    return (thisptr->start_ + thisptr->len_ - thisptr->cur_) > 0;
}

int NonAlignedCopyNext(NonAlignedCopy* thisptr, ssize_t* retOffset, ssize_t* retSize)
{
    ssize_t remaining = thisptr->start_ + thisptr->len_ - thisptr->cur_; // how much remains to be read?

    *retSize = thisptr->blockSize_ - (thisptr->cur_ % thisptr->blockSize_); // how much does this block have?
    if (*retSize > remaining)
    {
        *retSize = remaining;  // set size to MIN(remaining, available in block)
    }
    *retOffset = thisptr->cur_;

    thisptr->cur_ += *retSize; // increment cur ptr

    return 0;
}


#endif

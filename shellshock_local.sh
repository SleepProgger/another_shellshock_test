#!/bin/sh

if [ ! $(which bash)]; then
  echo "No bash found. You shouldn't be vulnerable."
  exit 1
fi

echo "check local 1 ('() { :;};') "
if [ $(env x='() { :;}; echo tHiSFlAg' bash -c echo; 2>/dev/null) = "tHiSFlAg" ]; then
  echo "vulnerable"
fi
echo "check local 2 ('() { (a)=>\') ..."
if [ $(rm -f echo; env X='() { (a)=>\' bash -c "echo echo tHiSFlAg" 2>/dev/null; cat echo; rm -f echo) = "tHiSFlAg" ]; then
  echo "vulnerable"
fi
